// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 7130 micro-BFD: BFD on LAG (bond) member links.
 *
 * A micro-BFD session runs on every member of a configured bond. The member
 * carries the bond's traffic only while its session is Up ("strict" mode):
 * when the session fails, bfdd asks zebra to take the member out of the bond
 * (detach, ZEBRA_LAG_MBFD_DIST_SET); when it comes back Up, to put it back
 * (attach). Zebra tells bfdd about the bond and its members
 * (ZEBRA_LAG_MBFD_BOND_STATUS / MEMBER_UPDATE) and re-attaches what bfdd
 * detached when bfdd goes away (fail-open).
 *
 * Packets (RFC 7130, Section 2): UDP destination port 6784, IP TTL 255,
 * Ethernet destination 01:00:5e:90:00:01, source address of the LAG, sent
 * directly on the member link. bfdd sends and reads them on one raw
 * (AF_PACKET) socket per member, bound to that member, so a packet is
 * always matched to the member it arrived on, and copies seen on the bond
 * or sent by bfdd itself never reach the session. A classic BPF filter
 * keeps everything but incoming untagged IPv4/UDP 6784 out of the socket.
 * A UDP socket on port 6784 per VRF, never read, keeps the kernel from
 * answering these packets with ICMP port unreachable.
 *
 * Strict mode, per member:
 * - enable-grace: after a session is created (configuration, bfdd start, a
 *   new member), the member is left alone for this long so the session can
 *   come Up first.
 * - Session Down: detach at once, unless in enable-grace, settling after
 *   an attach, or the member is protodown.
 * - Session Up while detached: wait hold-up, then attach.
 * - Attach bounces the member link (the bonding driver needs it down to
 *   enslave it), so the session goes Down again on both ends. Down is
 *   ignored until the member distributes with its session Up, for at most
 *   BFD_LAG_SETTLE_MAX.
 * - Shutdown, or a peer signalling AdminDown (RFC 5882, Section 3.2): not
 *   a failure, members are attached (fail-open).
 *
 * Copyright (C) 2026 Aviz Networks
 */

#include <zebra.h>

#ifdef BFD_LINUX
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#endif

#include "lib/if.h"
#include "lib/json.h"
#include "lib/network.h"
#include "lib/printfrr.h"
#include "lib/vrf.h"

#include "bfd.h"
#include "bfd_frame.h"
#include "bfd_lag.h"

DEFINE_MTYPE_STATIC(BFDD, BFDD_LAG, "BFD micro-BFD LAG");
DEFINE_MTYPE_STATIC(BFDD, BFDD_LAG_MEMBER, "BFD micro-BFD LAG member");
DEFINE_MTYPE_STATIC(BFDD, BFDD_LAG_PROFILE, "BFD micro-BFD LAG profile name");

static struct bfd_lags_head bfd_lags;

/* RFC 7130, Section 2.3: dedicated MAC address. */
static const uint8_t bfd_lag_dmac[ETH_ALEN] = { 0x01, 0x00, 0x5e, 0x90, 0x00, 0x01 };

static void lag_member_evaluate(struct bfd_lag_member *m);
static void lag_sessions_sync(struct bfd_lag *lag);
static void lag_member_session_delete(struct bfd_lag_member *m);
static void lag_addr_check_cb(struct event *t);
static void lag_addr_update(struct bfd_lag *lag, bool confirm);

#define LAG_DEBUG(fmt, ...)                                                                       \
	do {                                                                                      \
		if (bglobal.debug_lag)                                                            \
			zlog_debug("micro-BFD: " fmt, ##__VA_ARGS__);                             \
	} while (0)

const char *bfd_lag_mode2str(enum bfd_lag_mode mode)
{
	switch (mode) {
	case BFD_LAG_MODE_STRICT:
		return "strict";
	}

	return "unknown";
}

/*
 * Helpers.
 */
static struct interface *lag_if_by_name(const char *name)
{
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name_vrf(name, vrf);
		if (ifp && ifp->ifindex != IFINDEX_INTERNAL)
			return ifp;
	}

	return NULL;
}

static struct interface *lag_if_by_index(ifindex_t ifindex, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct vrf *vrf;

	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (ifp)
		return ifp;

	/* A member taken out of a bond in a VRF may be reported elsewhere. */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(ifindex, vrf->vrf_id);
		if (ifp)
			return ifp;
	}

	return NULL;
}

static struct bfd_lag *lag_by_ifindex(ifindex_t ifindex)
{
	struct bfd_lag *lag;

	if (ifindex == IFINDEX_INTERNAL)
		return NULL;

	frr_each (bfd_lags, &bfd_lags, lag)
		if (lag->ifindex == ifindex || lag->registered_ifindex == ifindex)
			return lag;

	return NULL;
}

static struct bfd_lag_member *lag_member_find(struct bfd_lag *lag, ifindex_t ifindex)
{
	struct bfd_lag_member *m;

	frr_each (bfd_lag_members, &lag->members, m)
		if (m->ifindex == ifindex)
			return m;

	return NULL;
}

static const char *lag_vrf_name(const struct bfd_lag *lag)
{
	struct vrf *vrf = vrf_lookup_by_id(lag->vrf_id);

	return vrf ? vrf->name : VRF_DEFAULT_NAME;
}

/* The primary (non secondary) IPv4 address of the bond. */
static struct in_addr lag_primary_ipv4(const struct bfd_lag *lag)
{
	struct in_addr none = { .s_addr = INADDR_ANY };
	const struct connected *ifc;
	struct interface *ifp;

	if (lag->ifindex == IFINDEX_INTERNAL)
		return none;

	ifp = lag_if_by_index(lag->ifindex, lag->vrf_id);
	if (!ifp)
		return none;

	frr_each (if_connected_const, ifp->connected, ifc) {
		if (!ifc->address || ifc->address->family != AF_INET)
			continue;
		if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY))
			continue;
		return ifc->address->u.prefix4;
	}

	return none;
}

static bool lag_member_detached(const struct bfd_lag_member *m)
{
	return CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_MBFD_DETACHED);
}

static bool lag_session_up(const struct bfd_lag_member *m)
{
	return m->bs4 && m->bs4->ses_state == PTM_BFD_UP;
}

/* Why the LAG runs no sessions (NULL: it can run them). */
static const char *lag_no_session_reason(const struct bfd_lag *lag)
{
	if (lag->ifindex == IFINDEX_INTERNAL)
		return "bond not found";
	if (!lag->status_known)
		return "waiting for zebra";
	switch (lag->status) {
	case ZAPI_LAG_BOND_OK:
		break;
	case ZAPI_LAG_BOND_NOT_FOUND:
		return "bond not found";
	case ZAPI_LAG_BOND_UNSUPPORTED_MODE:
		return "bond mode not supported (802.3ad or balance-xor only)";
	case ZAPI_LAG_BOND_EVPN_ES:
		return "bond is an EVPN Ethernet Segment";
	default:
		return "bond not usable";
	}
	if (!lag->use_ipv4 || !lag->has_dest4)
		return "no IPv4 destination address";
	if (lag->local4.s_addr == INADDR_ANY)
		return "no IPv4 source address";
	if (!bfd_vrf_is_permitted(lag_vrf_name(lag)))
		return "VRF not monitored (--vrfs)";
#ifndef BFD_LINUX
	return "not supported on this platform";
#endif

	return NULL;
}

/*
 * Zebra registration.
 */
static void lag_register(struct bfd_lag *lag)
{
	if (lag->registered || lag->ifindex == IFINDEX_INTERNAL || !bfdd_zclient_ready())
		return;

	if (bfdd_zclient_lag_register(lag->vrf_id, lag->ifindex, true) != 0) {
		zlog_warn("micro-BFD: lag %s: can't register with zebra", lag->name);
		return;
	}

	lag->registered = true;
	lag->registered_ifindex = lag->ifindex;
	LAG_DEBUG("lag %s: registered bond ifindex %u", lag->name, lag->ifindex);
}

static void lag_unregister(struct bfd_lag *lag)
{
	if (!lag->registered)
		return;

	if (bfdd_zclient_ready())
		bfdd_zclient_lag_register(lag->vrf_id, lag->registered_ifindex, false);

	LAG_DEBUG("lag %s: unregistered bond ifindex %u", lag->name, lag->registered_ifindex);
	lag->registered = false;
	lag->registered_ifindex = IFINDEX_INTERNAL;
	lag->status_known = false;
}

/* Find the bond (it may not exist yet) and register it with zebra. */
static void lag_resolve(struct bfd_lag *lag)
{
	struct interface *ifp = lag_if_by_name(lag->name);

	if (!ifp) {
		lag->ifindex = IFINDEX_INTERNAL;
		return;
	}

	if (lag->registered && lag->registered_ifindex != ifp->ifindex)
		lag_unregister(lag);

	lag->ifindex = ifp->ifindex;
	lag->vrf_id = ifp->vrf->vrf_id;
	lag_register(lag);
}

/*
 * Members.
 */
static struct bfd_lag_member *lag_member_new(struct bfd_lag *lag, const struct zapi_lag_member *zm)
{
	struct bfd_lag_member *m = XCALLOC(MTYPE_BFDD_LAG_MEMBER, sizeof(*m));

	m->lag = lag;
	m->ifindex = zm->mbr_ifindex;
	m->port_sock = -1;
	bfd_lag_members_add_tail(&lag->members, m);

	return m;
}

static void lag_member_free(struct bfd_lag_member *m)
{
	lag_member_session_delete(m);

	event_cancel(&m->t_grace);
	event_cancel(&m->t_holdup);
	event_cancel(&m->t_settle);
	event_cancel(&m->t_req);

	bfd_lag_members_del(&m->lag->members, m);
	XFREE(MTYPE_BFDD_LAG_MEMBER, m);
}

static void lag_members_free(struct bfd_lag *lag)
{
	struct bfd_lag_member *m;

	while ((m = bfd_lag_members_first(&lag->members)))
		lag_member_free(m);
}

/*
 * Sessions.
 */
static void lag_grace_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	m->in_grace = false;
	LAG_DEBUG("lag %s member %s: enable-grace over", m->lag->name, m->name);
	lag_member_evaluate(m);
}

static void lag_member_session_create(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;
	struct sockaddr_any peer = {}, local = {};
	char bfdname[BFD_NAME_SIZE + 1];
	struct bfd_session *bs;

	snprintf(bfdname, sizeof(bfdname), "%s%s", BFD_LAG_NAME_PREFIX, lag->name);

	peer.sa_sin.sin_family = AF_INET;
	peer.sa_sin.sin_addr = lag->dest4;
	local.sa_sin.sin_family = AF_INET;
	if (lag->has_src4)
		local.sa_sin.sin_addr = lag->src4;

	bs = bfd_session_new(BFD_MODE_TYPE_MICRO_BFD);
	gen_bfd_key(&bs->key, &peer, &local, false, m->name, lag_vrf_name(lag), bfdname);
	strlcpy(bs->bfd_name, bfdname, sizeof(bs->bfd_name));
	bs->lag_mbr = m;
	m->bs4 = bs;

	/* Local shutdown before the session starts, profile applied below. */
	bs->peer_profile.admin_shutdown = lag->admin_down;

	if (bfd_key_lookup(&bs->key)) {
		zlog_warn("micro-BFD: lag %s member %s: session exists already", lag->name,
			  m->name);
		m->bs4 = NULL;
		bs->lag_mbr = NULL;
		bfd_session_free(bs);
		return;
	}

	if (bs_registrate(bs) == NULL) {
		/* bs_registrate() freed it. */
		m->bs4 = NULL;
		return;
	}

	if (lag->profile_name)
		bfd_profile_apply(lag->profile_name, bs);
	else
		bfd_session_apply(bs);

	/* Give the session time to come Up before acting on it. */
	m->in_grace = lag->enable_grace > 0;
	m->holdup_done = false;
	event_cancel(&m->t_grace);
	if (m->in_grace)
		event_add_timer_msec(master, lag_grace_cb, m, lag->enable_grace, &m->t_grace);

	LAG_DEBUG("lag %s member %s: session created (%s)", lag->name, m->name, bs_to_string(bs));
}

static void lag_member_session_delete(struct bfd_lag_member *m)
{
	struct bfd_session *bs = m->bs4;

	if (!bs)
		return;

	LAG_DEBUG("lag %s member %s: session deleted", m->lag->name, m->name);

	/* bfd_session_free() unlinks it through bfd_lag_session_freed(). */
	bfd_session_free(bs);
	m->bs4 = NULL;
	m->in_grace = false;
	m->holdup_done = false;
	m->peer_admin_down = false;
	event_cancel(&m->t_grace);
	event_cancel(&m->t_holdup);
}

/* Create or delete the sessions of a LAG as the configuration allows. */
static void lag_sessions_sync(struct bfd_lag *lag)
{
	struct bfd_lag_member *m;
	bool want;

	if (lag->has_src4) {
		lag->local4 = lag->src4;
	} else {
		struct in_addr now = lag_primary_ipv4(lag);

		/* Losing it is lag_addr_update()'s decision. */
		if (now.s_addr != INADDR_ANY)
			lag->local4 = now;
		else if (lag->local4.s_addr != INADDR_ANY)
			lag_addr_update(lag, false);
	}
	want = lag_no_session_reason(lag) == NULL;

	frr_each (bfd_lag_members, &lag->members, m) {
		if (want && !m->bs4)
			lag_member_session_create(m);
		else if (!want && m->bs4)
			lag_member_session_delete(m);
		lag_member_evaluate(m);
	}
}

/* Delete and create again: the session key changed. */
static void lag_sessions_restart(struct bfd_lag *lag)
{
	struct bfd_lag_member *m;

	frr_each (bfd_lag_members, &lag->members, m)
		lag_member_session_delete(m);

	lag_sessions_sync(lag);
}

const char *bfd_lag_session_lag_name(const struct bfd_session *bs)
{
	return bs->lag_mbr ? bs->lag_mbr->lag->name : NULL;
}

/*
 * Sockets.
 */
#ifdef BFD_LINUX
/*
 * Incoming untagged IPv4/UDP to port 6784, not a fragment, not sent by us,
 * addressed to us. Offsets are from the start of the Ethernet header.
 */
static struct sock_filter bfd_lag_bpf[] = {
	/* 0: packet type: drop our own and other hosts' frames. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE),
	/* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_OUTGOING, 13, 0),
	/* 2 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_OTHERHOST, 12, 0),
	/* 3: VLAN tag the NIC took off. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT),
	/* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 10),
	/* 5: ethertype IPv4. */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
	/* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 8),
	/* 7: protocol UDP. */
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
	/* 8 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 6),
	/* 9: no fragments. */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),
	/* 10 */ BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x3fff, 4, 0),
	/* 11: X = IPv4 header length. */
	BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),
	/* 12: UDP destination port. */
	BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),
	/* 13 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BFD_LAG_PORT, 0, 1),
	/* 14: accept. */
	BPF_STMT(BPF_RET | BPF_K, 0xffff),
	/* 15: drop. */
	BPF_STMT(BPF_RET | BPF_K, 0),
};

static int lag_raw_socket(const struct bfd_lag_member *m, const struct vrf *vrf)
{
	struct sock_fprog prog = {
		.len = array_size(bfd_lag_bpf),
		.filter = bfd_lag_bpf,
	};
	struct packet_mreq mreq = {};
	struct sockaddr_ll sll = {};
	int sd;

	/* Protocol 0: nothing is queued before the filter is in place. */
	frr_with_privs (&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_PACKET, SOCK_RAW, 0, vrf->vrf_id, NULL);
	}
	if (sd < 0) {
		zlog_warn("micro-BFD: member %s: raw socket: %s", m->name, safe_strerror(errno));
		return -1;
	}

	if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
		zlog_warn("micro-BFD: member %s: SO_ATTACH_FILTER: %s", m->name,
			  safe_strerror(errno));
		goto fail;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = m->ifindex;
	if (bind(sd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		zlog_warn("micro-BFD: member %s: bind: %s", m->name, safe_strerror(errno));
		goto fail;
	}

	/* RFC 7130, Section 2.3: receive the dedicated MAC on the member. */
	mreq.mr_ifindex = m->ifindex;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	memcpy(mreq.mr_address, bfd_lag_dmac, ETH_ALEN);
	if (setsockopt(sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		zlog_warn("micro-BFD: member %s: PACKET_ADD_MEMBERSHIP: %s", m->name,
			  safe_strerror(errno));
		goto fail;
	}

	/* High priority on the member's queue, as other BFD sockets. */
	bp_set_prio(sd, BFD_LAG_SOCK_PRIO);
	set_nonblocking(sd);

	return sd;

fail:
	close(sd);
	return -1;
}

/*
 * RFC 5881, Section 4: a source port unique per session. A UDP socket bound
 * to it keeps it from other sessions (micro-BFD or not) for as long as the
 * session runs.
 */
static int lag_port_reserve(struct bfd_lag_member *m, const struct vrf *vrf)
{
	struct sockaddr_in sin = {};
	socklen_t slen = sizeof(sin);
	int sd;

	frr_with_privs (&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id, NULL);
	}
	if (sd < 0)
		return -1;

	sin.sin_family = AF_INET;
	if (bp_bind_src_port(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0 ||
	    getsockname(sd, (struct sockaddr *)&sin, &slen) < 0) {
		close(sd);
		return -1;
	}

	m->port_sock = sd;
	m->sport = ntohs(sin.sin_port);
	return 0;
}

/* The per VRF port 6784 sink (see bfd.h, bg_mbfd). */
static void lag_sink_ref(struct vrf *vrf)
{
	struct bfd_vrf_global *bvrf = vrf->info;
	struct sockaddr_in sin = {};
	int sd, one = 1;

	if (!bvrf)
		return;
	if (bvrf->bg_mbfd_count++ > 0 || bvrf->bg_mbfd != -1)
		return;

	frr_with_privs (&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id, vrf->name);
	}
	if (sd < 0) {
		zlog_warn("micro-BFD: VRF %s: UDP %d socket: %s", vrf->name, BFD_LAG_PORT,
			  safe_strerror(errno));
		return;
	}

	/* Never read; keep its queue small. */
	setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &one, sizeof(one));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(BFD_LAG_PORT);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		zlog_warn("micro-BFD: VRF %s: bind UDP %d: %s", vrf->name, BFD_LAG_PORT,
			  safe_strerror(errno));
		close(sd);
		return;
	}

	bvrf->bg_mbfd = sd;
}

static void lag_sink_unref(struct vrf *vrf)
{
	struct bfd_vrf_global *bvrf = vrf ? vrf->info : NULL;

	if (!bvrf || bvrf->bg_mbfd_count == 0)
		return;
	if (--bvrf->bg_mbfd_count > 0)
		return;

	if (bvrf->bg_mbfd != -1) {
		close(bvrf->bg_mbfd);
		bvrf->bg_mbfd = -1;
	}
}
#endif /* BFD_LINUX */

void bfd_lag_vrf_disable(struct bfd_vrf_global *bvrf)
{
	if (bvrf->bg_mbfd != -1) {
		close(bvrf->bg_mbfd);
		bvrf->bg_mbfd = -1;
	}
	bvrf->bg_mbfd_count = 0;
}

#ifdef BFD_LINUX
static void lag_recv_cb(struct event *t);
#endif

int bfd_lag_session_enable(struct bfd_session *bs)
{
#ifdef BFD_LINUX
	struct bfd_lag_member *m = bs->lag_mbr;
	struct interface *ifp;
	struct vrf *vrf;
	int sd;

	if (!m)
		return 0;

	vrf = vrf_lookup_by_id(m->lag->vrf_id);
	if (!vrf || !vrf->info)
		return 0;

	ifp = lag_if_by_index(m->ifindex, vrf->vrf_id);
	if (!ifp)
		return 0;

	if (m->lag->local4.s_addr == INADDR_ANY)
		return 0;

	if (bs->sock != -1)
		return 0;

	if (m->port_sock == -1 && lag_port_reserve(m, vrf) < 0) {
		zlog_warn("micro-BFD: member %s: no source port available", m->name);
		return 0;
	}

	sd = lag_raw_socket(m, vrf);
	if (sd < 0) {
		close(m->port_sock);
		m->port_sock = -1;
		return 0;
	}

	bs->vrf = vrf;
	bs->ifp = ifp;
	bs->sock = sd;
	memset(&bs->local_address, 0, sizeof(bs->local_address));
	bs->local_address.sa_sin.sin_family = AF_INET;
	bs->local_address.sa_sin.sin_addr = m->lag->local4;

	lag_sink_ref(vrf);
	event_add_read(master, lag_recv_cb, m, sd, &m->t_read);

	/* Micro-BFD is never passive: start right away. */
	bfd_recvtimer_update(bs);
	ptm_bfd_start_xmt_timer(bs, false);
	bfd_rtt_init(bs);

	LAG_DEBUG("member %s: session enabled, source port %u", m->name, m->sport);
#endif /* BFD_LINUX */
	return 0;
}

void bfd_lag_session_disable(struct bfd_session *bs)
{
	struct bfd_lag_member *m = bs->lag_mbr;

	if (m) {
		event_cancel(&m->t_read);
		if (m->port_sock != -1) {
			close(m->port_sock);
			m->port_sock = -1;
		}
	}

	if (bs->sock != -1) {
#ifdef BFD_LINUX
		lag_sink_unref(bs->vrf);
#endif
		close(bs->sock);
		bs->sock = -1;
	}

	bfd_recvtimer_delete(bs);
	bfd_xmttimer_delete(bs);
	ptm_bfd_echo_stop(bs);
	bs->vrf = NULL;
	bs->ifp = NULL;

	/* Set session down so it doesn't report UP and disabled. */
	ptm_bfd_sess_dn(bs, BD_PATH_DOWN, false);
}

void bfd_lag_session_freed(struct bfd_session *bs)
{
	struct bfd_lag_member *m = bs->lag_mbr;

	/*
	 * Unlink first: the session going down on its way out must not
	 * make the member act on it.
	 */
	bs->lag_mbr = NULL;
	if (m) {
		if (m->bs4 == bs)
			m->bs4 = NULL;
		event_cancel(&m->t_read);
		if (m->port_sock != -1) {
			close(m->port_sock);
			m->port_sock = -1;
		}
	}

	bfd_lag_session_disable(bs);
}

int bfd_lag_send(struct bfd_session *bs, const void *data, size_t len)
{
#ifdef BFD_LINUX
	struct bfd_lag_member *m = bs->lag_mbr;
	struct bfd_frame_params fp = {};
	struct sockaddr_ll sll = {};
	uint8_t frame[BFD_FRAME_MAX_HLEN + 256];
	ssize_t flen;

	if (!m || bs->sock == -1)
		return -1;

	fp.family = AF_INET;
	/* The member's own (current) MAC: the bond's while it's attached. */
	memcpy(fp.smac, m->mac, ETH_ALEN);
	if (bs->ifp && !memcmp(fp.smac, "\0\0\0\0\0\0", ETH_ALEN) &&
	    bs->ifp->hw_addr_len == ETH_ALEN)
		memcpy(fp.smac, bs->ifp->hw_addr, ETH_ALEN);
	memcpy(fp.dmac, bfd_lag_dmac, ETH_ALEN);
	fp.src.v4 = m->lag->local4;
	fp.dst.v4 = m->lag->dest4;
	fp.sport = m->sport;
	fp.dport = BFD_LAG_PORT;
	fp.ttl = BFD_TTL_VAL;
	fp.tos = BFD_TOS_VAL;
	fp.ip_id = (uint16_t)frr_weak_random();

	flen = bfd_frame_build(frame, sizeof(frame), &fp, data, len);
	if (flen < 0) {
		m->stats.tx_errors++;
		return -1;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = m->ifindex;
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, bfd_lag_dmac, ETH_ALEN);

	if (sendto(bs->sock, frame, flen, 0, (struct sockaddr *)&sll, sizeof(sll)) != flen) {
		m->stats.tx_errors++;
		if (bglobal.debug_network)
			zlog_debug("micro-BFD: member %s: send: %s", m->name, safe_strerror(errno));
		return -1;
	}

	m->stats.tx_frames++;
	return 0;
#else
	return -1;
#endif /* BFD_LINUX */
}

#ifdef BFD_LINUX
static void lag_recv_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);
	int sd = EVENT_FD(t);
	union {
		struct bfd_pkt cp;
		uint8_t buf[BFD_PACKET_SIZE];
	} pkt;
	uint8_t frame[BFD_PACKET_SIZE + BFD_FRAME_MAX_HLEN];
	struct sockaddr_ll sll = {};
	socklen_t slen = sizeof(sll);
	struct bfd_frame_info fi;
	struct bfd_session *bs;
	struct bfd_ctrl_rx rx = {};
	struct bfd_lag *lag;
	ssize_t n;
	int rv;

	event_add_read(master, lag_recv_cb, m, sd, &m->t_read);

	n = recvfrom(sd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, &slen);
	if (n < 0) {
		if (!ERRNO_IO_RETRY(errno) && bglobal.debug_network)
			zlog_debug("micro-BFD: member %s: recv: %s", m->name, safe_strerror(errno));
		return;
	}

	m->stats.rx_frames++;
	lag = m->lag;

	/* Bound to the member, filtered: belt and braces. */
	if (sll.sll_ifindex != m->ifindex || sll.sll_pkttype == PACKET_OUTGOING ||
	    sll.sll_pkttype == PACKET_OTHERHOST) {
		m->stats.rx_mismatch++;
		return;
	}

	rv = bfd_frame_parse(frame, n, &fi);
	if (rv != BFD_FRAME_OK) {
		m->stats.rx_bad_frame++;
		if (bglobal.debug_network)
			zlog_debug("micro-BFD: member %s: dropped frame: %s", m->name,
				   bfd_frame_parse_strerror(rv));
		return;
	}

	/* The LAG's addresses, both ways (RFC 7130, Section 2.1). */
	if (fi.family != AF_INET || fi.dport != BFD_LAG_PORT ||
	    fi.src.v4.s_addr != lag->dest4.s_addr || fi.dst.v4.s_addr != lag->local4.s_addr) {
		m->stats.rx_mismatch++;
		if (bglobal.debug_network)
			zlog_debug("micro-BFD: member %s: dropped packet %pI4 -> %pI4 port %u: not this LAG's",
				   m->name, &fi.src.v4, &fi.dst.v4, fi.dport);
		return;
	}

	if (fi.plen < BFD_PKT_LEN || fi.plen > sizeof(pkt.buf)) {
		m->stats.rx_bad_frame++;
		return;
	}

	bs = m->bs4;
	if (!bs) {
		m->stats.rx_no_session++;
		return;
	}

	/* Aligned copy of the BFD packet. */
	memcpy(pkt.buf, fi.payload, fi.plen);

	/*
	 * The session on this member is the only one this packet can be
	 * for: a Your Discriminator of any other session is refused, even one
	 * of the same LAG on another member.
	 */
	if (pkt.cp.discrs.remote_discr && ntohl(pkt.cp.discrs.remote_discr) != bs->discrs.my_discr) {
		m->stats.rx_wrong_discr++;
		if (bglobal.debug_network)
			zlog_debug("micro-BFD: member %s: Your Discriminator %u is not %u",
				   m->name, ntohl(pkt.cp.discrs.remote_discr), bs->discrs.my_discr);
		return;
	}

	rx.sd = sd;
	rx.is_mhop = false;
	rx.ttl = fi.ttl;
	rx.ifindex = m->ifindex;
	rx.ifp = bs->ifp;
	rx.vrfid = bs->vrf ? bs->vrf->vrf_id : lag->vrf_id;
	rx.peer.sa_sin.sin_family = AF_INET;
	rx.peer.sa_sin.sin_addr = fi.src.v4;
	rx.peer.sa_sin.sin_port = htons(fi.sport);
	rx.local.sa_sin.sin_family = AF_INET;
	rx.local.sa_sin.sin_addr = fi.dst.v4;
	rx.local.sa_sin.sin_port = htons(fi.dport);

	bfd_ctrl_pkt_process(bs, &pkt.cp, fi.plen, &rx);
}
#endif /* BFD_LINUX */

/*
 * Strict mode.
 */
static void lag_req_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	/* Zebra didn't answer: decide again. */
	m->req_outstanding = false;
	lag_member_evaluate(m);
}

static void lag_settle_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	m->settling = false;
	LAG_DEBUG("lag %s member %s: attach-settle ceiling reached", m->lag->name, m->name);
	lag_member_evaluate(m);
}

static void lag_holdup_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	m->holdup_done = true;
	lag_member_evaluate(m);
}

static void lag_member_request(struct bfd_lag_member *m, bool attach, const char *why)
{
	struct bfd_lag *lag = m->lag;

	if (bfdd_zclient_lag_dist_set(lag->vrf_id, lag->ifindex, m->ifindex, attach) != 0) {
		zlog_warn("micro-BFD: lag %s member %s: can't ask zebra to %s it", lag->name,
			  m->name, attach ? "attach" : "detach");
		return;
	}

	zlog_info("micro-BFD: lag %s member %s: %s, %s", lag->name, m->name, why,
		  attach ? "attaching" : "detaching");

	m->req_outstanding = true;
	m->req_attach = attach;
	monotime(&m->last_action);
	event_cancel(&m->t_req);
	event_add_timer_msec(master, lag_req_cb, m, BFD_LAG_REQ_TIMEOUT, &m->t_req);

	if (attach) {
		m->stats.attach_count++;
		/* The link bounces: ignore Down until it's back. */
		m->settling = true;
		event_cancel(&m->t_settle);
		event_add_timer_msec(master, lag_settle_cb, m, BFD_LAG_SETTLE_MAX, &m->t_settle);
	} else {
		m->stats.detach_count++;
		m->settling = false;
		event_cancel(&m->t_settle);
	}
	m->holdup_done = false;
	event_cancel(&m->t_holdup);
}

/* A keychain without a key the session can use: it sends nothing. */
static bool lag_member_auth_broken(const struct bfd_lag_member *m)
{
	const struct bfd_session *bs = m->bs4;

	return bs && bs->kc && !bfd_keychain_key_find_active(bs->kc, bs->auth_meticulous);
}

/*
 * Decide whether the member should carry traffic, and ask zebra for the
 * change. Called on every event that could change the answer.
 */
static void lag_member_evaluate(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;
	struct bfd_session *bs = m->bs4;
	bool detached = lag_member_detached(m);
	const char *fail_open = NULL;

	if (!lag->registered || lag->ifindex == IFINDEX_INTERNAL)
		return;

	/* Wait for the kernel, and for zebra to answer the last request. */
	if (CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PENDING) || m->req_outstanding)
		return;

	/* Not a failure: don't keep members out (fail-open). */
	if (!bs)
		fail_open = lag_no_session_reason(lag);
	else if (bs->ses_state == PTM_BFD_ADM_DOWN)
		fail_open = "shutdown";
	else if (m->peer_admin_down && bs->ses_state != PTM_BFD_UP)
		fail_open = "peer signalled AdminDown";

	if (fail_open) {
		m->reason = fail_open;
		m->settling = false;
		event_cancel(&m->t_settle);
		event_cancel(&m->t_holdup);
		if (detached)
			lag_member_request(m, true, fail_open);
		return;
	}

	if (lag_session_up(m)) {
		if (detached) {
			if (lag->hold_up && !m->holdup_done) {
				m->reason = "hold-up";
				if (!event_is_scheduled(m->t_holdup))
					event_add_timer_msec(master, lag_holdup_cb, m,
							     lag->hold_up, &m->t_holdup);
				return;
			}
			lag_member_request(m, true, "session up");
			return;
		}

		if (m->settling) {
			if (!CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_DISTRIBUTING)) {
				m->reason = "attach-settle";
				return;
			}
			m->settling = false;
			event_cancel(&m->t_settle);
			LAG_DEBUG("lag %s member %s: settled", lag->name, m->name);
		}
		m->reason = NULL;
		return;
	}

	/* Session not Up. */
	m->holdup_done = false;
	event_cancel(&m->t_holdup);

	if (detached) {
		m->reason = lag_member_auth_broken(m) ? "auth: no usable key" : "session down";
		return;
	}
	if (m->in_grace) {
		m->reason = "enable-grace";
		return;
	}
	if (m->settling) {
		m->reason = "attach-settle";
		return;
	}
	if (CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PROTODOWN)) {
		m->reason = "protodown";
		return;
	}

	m->reason = lag_member_auth_broken(m) ? "auth: no usable key" : "session down";
	lag_member_request(m, false, m->reason);
}

void bfd_lag_session_notify(struct bfd_session *bs, uint8_t state)
{
	struct bfd_lag_member *m = bs->lag_mbr;

	if (!m)
		return;

	switch (state) {
	case PTM_BFD_UP:
		m->peer_admin_down = false;
		break;
	case PTM_BFD_ADM_DOWN:
		/* Local shutdown has the session AdminDown itself. */
		if (bs->ses_state != PTM_BFD_ADM_DOWN)
			m->peer_admin_down = true;
		break;
	default:
		m->peer_admin_down = false;
		break;
	}

	LAG_DEBUG("lag %s member %s: session %s%s", m->lag->name, m->name,
		  state_list[bs->ses_state].str, m->peer_admin_down ? " (peer AdminDown)" : "");

	lag_member_evaluate(m);
}

/*
 * Zebra events.
 */
static void lag_stale_cb(struct event *t)
{
	struct bfd_lag *lag = EVENT_ARG(t);
	struct bfd_lag_member *m;

	frr_each_safe (bfd_lag_members, &lag->members, m) {
		if (!m->stale)
			continue;
		LAG_DEBUG("lag %s member %s: no longer reported by zebra", lag->name, m->name);
		lag_member_free(m);
	}
}

void bfd_lag_zebra_connected(void)
{
	struct bfd_lag_member *m;
	struct bfd_lag *lag;

	frr_each (bfd_lags, &bfd_lags, lag) {
		/*
		 * Zebra lost our registration. Keep the sessions running
		 * (their peers would see them fail otherwise); members zebra
		 * doesn't report again are dropped later.
		 */
		lag->registered = false;
		lag->registered_ifindex = IFINDEX_INTERNAL;
		lag->status_known = false;
		frr_each (bfd_lag_members, &lag->members, m) {
			m->stale = true;
			m->req_outstanding = false;
			event_cancel(&m->t_req);
		}
		event_cancel(&lag->t_stale);
		event_add_timer_msec(master, lag_stale_cb, lag, BFD_LAG_STALE_TIMEOUT,
				     &lag->t_stale);
		lag_resolve(lag);
	}
}

void bfd_lag_zebra_bond_status(vrf_id_t vrf_id, const struct zapi_lag_bond_status *st)
{
	struct bfd_lag *lag = lag_by_ifindex(st->bond_ifindex);

	if (!lag)
		return;

	LAG_DEBUG("lag %s: bond status %s, mode %u, %u members", lag->name,
		  zapi_lag_bond_status2str(st->status), st->bond_mode, st->member_count);

	if (!lag->status_known || lag->status != st->status) {
		if (st->status != ZAPI_LAG_BOND_OK)
			zlog_info("micro-BFD: lag %s: %s", lag->name,
				  zapi_lag_bond_status2str(st->status));
	}

	lag->status_known = true;
	lag->status = st->status;
	lag->bond_mode = st->bond_mode;

	if (st->status == ZAPI_LAG_BOND_NOT_FOUND) {
		/* Gone: forget it, register again when a bond of that name appears. */
		lag_members_free(lag);
		lag_unregister(lag);
		lag->ifindex = IFINDEX_INTERNAL;
		return;
	}

	if (st->status != ZAPI_LAG_BOND_OK) {
		/* No member updates follow for an unusable bond. */
		lag_members_free(lag);
		return;
	}

	lag_sessions_sync(lag);
}

void bfd_lag_zebra_member(vrf_id_t vrf_id, const struct zapi_lag_member *zm)
{
	struct bfd_lag *lag = lag_by_ifindex(zm->bond_ifindex);
	struct bfd_lag_member *m;
	bool changed_mac;
	char buf[128];

	if (!lag)
		return;

	LAG_DEBUG("lag %s: member %s %s, flags %s, ad 0x%02x", lag->name, zm->mbr_name,
		  zapi_lag_mbr_op2str(zm->op), zapi_lag_mbr_flags2str(zm->flags, buf, sizeof(buf)),
		  zm->ad_actor_state);

	m = lag_member_find(lag, zm->mbr_ifindex);

	if (zm->op == ZAPI_LAG_MBR_DEL) {
		if (m) {
			zlog_info("micro-BFD: lag %s: member %s left the bond", lag->name, m->name);
			lag_member_free(m);
		}
		return;
	}

	if (!m)
		m = lag_member_new(lag, zm);

	changed_mac = memcmp(m->mac, zm->mac, ETH_ALEN) != 0;
	strlcpy(m->name, zm->mbr_name, sizeof(m->name));
	memcpy(m->mac, zm->mac, ETH_ALEN);
	m->zflags = zm->flags;
	m->ad_state = zm->ad_actor_state;
	m->stale = false;

	/*
	 * Zebra answered the last request: the member is pending, or in the
	 * state asked for. Other updates may cross the request.
	 */
	if (m->req_outstanding && (CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PENDING) ||
				   lag_member_detached(m) != m->req_attach)) {
		m->req_outstanding = false;
		event_cancel(&m->t_req);
	}

	if (changed_mac && m->bs4)
		LAG_DEBUG("lag %s member %s: MAC now %pEA", lag->name, m->name,
			  (struct ethaddr *)m->mac);

	if (!m->bs4 && lag_no_session_reason(lag) == NULL)
		lag_member_session_create(m);

	lag_member_evaluate(m);
}

void bfd_lag_if_add(struct interface *ifp)
{
	struct bfd_lag *lag;

	frr_each (bfd_lags, &bfd_lags, lag) {
		if (strcmp(lag->name, ifp->name))
			continue;
		lag_resolve(lag);
	}
}

void bfd_lag_if_del(struct interface *ifp)
{
	struct bfd_lag *lag;

	frr_each (bfd_lags, &bfd_lags, lag) {
		if (lag->ifindex != ifp->ifindex)
			continue;
		lag_members_free(lag);
		lag_unregister(lag);
		lag->ifindex = IFINDEX_INTERNAL;
	}
}

/*
 * The bond's source address changed, or may have.
 *
 * Zebra withdraws the addresses of an interface that goes operationally
 * down, and a bond does when micro-BFD took all its members out; it sends
 * them again when the bond comes up. The address is still there all along,
 * and the sessions that bring the members back need it. So an address that
 * disappears is only given up when it is still gone a moment later with the
 * bond up. A new or different address is taken at once.
 */
static void lag_addr_update(struct bfd_lag *lag, bool confirm)
{
	struct bfd_lag_member *m;
	struct interface *ifp;
	struct in_addr old, now;

	if (lag->has_src4 || lag->ifindex == IFINDEX_INTERNAL)
		return;

	old = lag->local4;
	now = lag_primary_ipv4(lag);

	if (now.s_addr == INADDR_ANY && old.s_addr != INADDR_ANY) {
		ifp = lag_if_by_index(lag->ifindex, lag->vrf_id);
		if (!confirm || !ifp || !if_is_operative(ifp)) {
			if (!event_is_scheduled(lag->t_addr))
				event_add_timer_msec(master, lag_addr_check_cb, lag,
						     BFD_LAG_ADDR_CHECK, &lag->t_addr);
			return;
		}
	}

	event_cancel(&lag->t_addr);
	if (old.s_addr == now.s_addr)
		return;

	zlog_info("micro-BFD: lag %s: IPv4 source address %pI4 -> %pI4", lag->name, &old, &now);
	lag->local4 = now;

	/* New address: sockets and packets need it. */
	frr_each (bfd_lag_members, &lag->members, m)
		lag_member_session_delete(m);
	lag_sessions_sync(lag);
}

static void lag_addr_check_cb(struct event *t)
{
	struct bfd_lag *lag = EVENT_ARG(t);
	struct interface *ifp;

	ifp = lag->ifindex != IFINDEX_INTERNAL ? lag_if_by_index(lag->ifindex, lag->vrf_id) : NULL;

	/* Still down: keep the address and look again later. */
	if (ifp && !if_is_operative(ifp)) {
		event_add_timer_msec(master, lag_addr_check_cb, lag, BFD_LAG_ADDR_CHECK,
				     &lag->t_addr);
		return;
	}

	lag_addr_update(lag, true);
}

void bfd_lag_if_address(struct interface *ifp)
{
	struct bfd_lag *lag;

	frr_each (bfd_lags, &bfd_lags, lag)
		if (lag->ifindex == ifp->ifindex)
			lag_addr_update(lag, false);
}

/*
 * Configuration.
 */
struct bfd_lag *bfd_lag_find(const char *name)
{
	struct bfd_lag *lag;

	frr_each (bfd_lags, &bfd_lags, lag)
		if (strcmp(lag->name, name) == 0)
			return lag;

	return NULL;
}

struct bfd_lag *bfd_lag_new(const char *name)
{
	struct bfd_lag *lag = bfd_lag_find(name);

	if (lag)
		return lag;

	lag = XCALLOC(MTYPE_BFDD_LAG, sizeof(*lag));
	strlcpy(lag->name, name, sizeof(lag->name));
	lag->mode = BFD_LAG_MODE_STRICT;
	lag->enable_grace = BFD_LAG_ENABLE_GRACE_DEF;
	lag->hold_up = BFD_LAG_HOLD_UP_DEF;
	lag->ifindex = IFINDEX_INTERNAL;
	lag->vrf_id = VRF_DEFAULT;
	bfd_lag_members_init(&lag->members);
	bfd_lags_add_tail(&bfd_lags, lag);

	lag_resolve(lag);

	return lag;
}

void bfd_lag_free(struct bfd_lag *lag)
{
	/* Zebra re-attaches what we detached. */
	lag_unregister(lag);
	lag_members_free(lag);
	event_cancel(&lag->t_stale);
	event_cancel(&lag->t_addr);
	XFREE(MTYPE_BFDD_LAG_PROFILE, lag->profile_name);
	bfd_lag_members_fini(&lag->members);
	bfd_lags_del(&bfd_lags, lag);
	XFREE(MTYPE_BFDD_LAG, lag);
}

void bfd_lag_free_all(void)
{
	struct bfd_lag *lag;

	while ((lag = bfd_lags_first(&bfd_lags)))
		bfd_lag_free(lag);
}

void bfd_lag_set_use_ipv4(struct bfd_lag *lag, bool use)
{
	lag->use_ipv4 = use;
}

void bfd_lag_set_ipv4_dest(struct bfd_lag *lag, const struct in_addr *addr)
{
	bool has = addr != NULL;

	if (has == lag->has_dest4 && (!has || addr->s_addr == lag->dest4.s_addr))
		return;

	lag->has_dest4 = has;
	lag->dest4.s_addr = has ? addr->s_addr : INADDR_ANY;
	lag_sessions_restart(lag);
}

void bfd_lag_set_ipv4_source(struct bfd_lag *lag, const struct in_addr *addr)
{
	bool has = addr != NULL;

	if (has == lag->has_src4 && (!has || addr->s_addr == lag->src4.s_addr))
		return;

	lag->has_src4 = has;
	lag->src4.s_addr = has ? addr->s_addr : INADDR_ANY;
	lag_sessions_restart(lag);
}

void bfd_lag_set_admin_down(struct bfd_lag *lag, bool admin_down)
{
	struct bfd_lag_member *m;

	lag->admin_down = admin_down;

	frr_each (bfd_lag_members, &lag->members, m) {
		if (!m->bs4)
			continue;
		if (!admin_down) {
			/* Back from shutdown: give the session time again. */
			m->in_grace = lag->enable_grace > 0;
			event_cancel(&m->t_grace);
			if (m->in_grace)
				event_add_timer_msec(master, lag_grace_cb, m, lag->enable_grace,
						     &m->t_grace);
		}
		m->bs4->peer_profile.admin_shutdown = admin_down;
		bfd_session_apply(m->bs4);
	}
}

void bfd_lag_set_profile(struct bfd_lag *lag, const char *profile)
{
	struct bfd_lag_member *m;

	XFREE(MTYPE_BFDD_LAG_PROFILE, lag->profile_name);
	if (profile)
		lag->profile_name = XSTRDUP(MTYPE_BFDD_LAG_PROFILE, profile);

	frr_each (bfd_lag_members, &lag->members, m) {
		if (!m->bs4)
			continue;
		if (profile)
			bfd_profile_apply(profile, m->bs4);
		else
			bfd_profile_remove(m->bs4);
	}
}

void bfd_lag_set_mode(struct bfd_lag *lag, enum bfd_lag_mode mode)
{
	lag->mode = mode;
}

void bfd_lag_set_enable_grace(struct bfd_lag *lag, uint32_t ms)
{
	lag->enable_grace = ms;
}

void bfd_lag_set_hold_up(struct bfd_lag *lag, uint32_t ms)
{
	lag->hold_up = ms;
}

/* After a configuration change: start, stop or re-evaluate sessions. */
void bfd_lag_apply(struct bfd_lag *lag)
{
	lag_resolve(lag);
	lag_sessions_sync(lag);
}

void bfd_lag_init(void)
{
	bfd_lags_init(&bfd_lags);
}

void bfd_lag_terminate(void)
{
	struct bfd_lag *lag;

	/*
	 * Shutting down: zebra re-attaches our members when we disconnect,
	 * no need to unregister.
	 */
	frr_each (bfd_lags, &bfd_lags, lag)
		lag->registered = false;

	bfd_lag_free_all();
	bfd_lags_fini(&bfd_lags);
}

/*
 * Northbound operational state.
 */
const struct bfd_lag *bfd_lag_next(const struct bfd_lag *lag)
{
	if (!lag)
		return bfd_lags_const_first(&bfd_lags);
	return bfd_lags_const_next(&bfd_lags, lag);
}

/* Member sessions of a LAG, in member order. */
const struct bfd_session *bfd_lag_session_next(const struct bfd_lag *lag,
					       const struct bfd_session *bs)
{
	const struct bfd_lag_member *m;

	if (!lag)
		return NULL;

	m = bs ? bs->lag_mbr : NULL;
	if (bs && !m)
		return NULL;
	m = m ? bfd_lag_members_const_next(&lag->members, m)
	      : bfd_lag_members_const_first(&lag->members);
	for (; m; m = bfd_lag_members_const_next(&lag->members, m))
		if (m->bs4)
			return m->bs4;

	return NULL;
}

const struct bfd_session *bfd_lag_session_find(const struct bfd_lag *lag, const char *ifname)
{
	const struct bfd_lag_member *m;

	if (!lag)
		return NULL;

	frr_each (bfd_lag_members_const, &lag->members, m)
		if (m->bs4 && strcmp(m->name, ifname) == 0)
			return m->bs4;

	return NULL;
}

bool bfd_lag_session_detached(const struct bfd_session *bs)
{
	return bs->lag_mbr && lag_member_detached(bs->lag_mbr);
}

bool bfd_lag_session_distributing(const struct bfd_session *bs)
{
	return bs->lag_mbr && CHECK_FLAG(bs->lag_mbr->zflags, ZAPI_LAG_MBR_F_DISTRIBUTING);
}

const char *bfd_lag_session_reason(const struct bfd_session *bs)
{
	return bs->lag_mbr ? bs->lag_mbr->reason : NULL;
}

/*
 * Show.
 */
static const char *lag_status_str(const struct bfd_lag *lag)
{
	if (lag->ifindex == IFINDEX_INTERNAL)
		return "bond-not-found";
	if (!lag->registered || !lag->status_known)
		return "waiting-for-zebra";
	return zapi_lag_bond_status2str(lag->status);
}

/* Detection time in ms (local view), 0 if unknown. */
static uint32_t lag_member_detect_ms(const struct bfd_lag_member *m)
{
	const struct bfd_session *bs = m->bs4;

	if (!bs)
		return 0;

	return bs->detect_mult * MAX(bs->timers.required_min_rx, bs->timers.desired_min_tx) / 1000;
}

static void lag_member_show(struct vty *vty, struct bfd_lag_member *m, json_object *jm)
{
	struct bfd_session *bs = m->bs4;
	bool detached = lag_member_detached(m);
	bool distributing = CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_DISTRIBUTING);
	const char *reason = m->reason ? m->reason : "";
	char buf[128];

	if (jm) {
		json_object_int_add(jm, "ifindex", m->ifindex);
		json_object_boolean_add(jm, "detached", detached);
		json_object_boolean_add(jm, "distributing", distributing);
		json_object_boolean_add(jm, "kernelAttached",
					CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_KERNEL_ATTACHED));
		json_object_boolean_add(jm, "pending",
					CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PENDING));
		json_object_string_add(jm, "zebraFlags",
				       zapi_lag_mbr_flags2str(m->zflags, buf, sizeof(buf)));
		json_object_string_add(jm, "reason", reason);
		json_object_boolean_add(jm, "enableGrace", m->in_grace);
		json_object_boolean_add(jm, "settling", m->settling);
		json_object_boolean_add(jm, "peerAdminDown", m->peer_admin_down);
		json_object_int_add(jm, "detachCount", m->stats.detach_count);
		json_object_int_add(jm, "attachCount", m->stats.attach_count);
		json_object_int_add(jm, "rxFrames", m->stats.rx_frames);
		json_object_int_add(jm, "rxBadFrame", m->stats.rx_bad_frame);
		json_object_int_add(jm, "rxMismatch", m->stats.rx_mismatch);
		json_object_int_add(jm, "rxWrongDiscriminator", m->stats.rx_wrong_discr);
		json_object_int_add(jm, "rxNoSession", m->stats.rx_no_session);
		json_object_int_add(jm, "txFrames", m->stats.tx_frames);
		json_object_int_add(jm, "txErrors", m->stats.tx_errors);
		if (bs) {
			json_object *js = json_object_new_object();

			/* RFC 9314 session-running names. */
			json_object_string_add(js, "localState", state_list[bs->ses_state].str);
			json_object_string_add(js, "remoteState",
					       state_list[bs->remote_ses_state].str);
			json_object_string_add(js, "localDiagnostic", diag2str(bs->local_diag));
			json_object_string_add(js, "remoteDiagnostic", diag2str(bs->remote_diag));
			json_object_int_add(js, "localDiscriminator", bs->discrs.my_discr);
			json_object_int_add(js, "remoteDiscriminator", bs->discrs.remote_discr);
			json_object_int_add(js, "localMultiplier", bs->detect_mult);
			json_object_int_add(js, "remoteMultiplier", bs->remote_detect_mult);
			json_object_int_add(js, "desiredMinTxInterval",
					    bs->timers.desired_min_tx / 1000);
			json_object_int_add(js, "requiredMinRxInterval",
					    bs->timers.required_min_rx / 1000);
			json_object_int_add(js, "negotiatedTxInterval",
					    bs->cur_timers.desired_min_tx / 1000);
			json_object_int_add(js, "negotiatedRxInterval",
					    bs->cur_timers.required_min_rx / 1000);
			json_object_int_add(js, "detectionTime", bs->detect_TO / 1000);
			json_object_int_add(js, "sourcePort", m->sport);
			json_object_int_add(js, "sessionUpCount", bs->stats.session_up);
			json_object_int_add(js, "sessionDownCount", bs->stats.session_down);
			json_object_int_add(js, "controlPacketInputCount", bs->stats.rx_ctrl_pkt);
			json_object_int_add(js, "controlPacketInputCountBad",
					    bs->stats.rx_bad_ctrl_pkt);
			json_object_int_add(js, "controlPacketOutputCount", bs->stats.tx_ctrl_pkt);
			json_object_object_add(jm, "microBfdIpv4", js);
		}
		return;
	}

	vty_out(vty, "    member %s: %s, %s%s\n", m->name,
		bs ? state_list[bs->ses_state].str : "no session",
		detached ? "detached" : "attached", distributing ? ", distributing" : "");
	if (bs) {
		vty_out(vty,
			"      session: local %s/%u remote %s/%u, multiplier %u/%u, detection %" PRIu64
			" ms, source port %u\n",
			state_list[bs->ses_state].str, bs->discrs.my_discr,
			state_list[bs->remote_ses_state].str, bs->discrs.remote_discr,
			bs->detect_mult, bs->remote_detect_mult, bs->detect_TO / 1000, m->sport);
		vty_out(vty, "      diagnostics: local %s, remote %s\n", diag2str(bs->local_diag),
			diag2str(bs->remote_diag));
	}
	if (m->reason)
		vty_out(vty, "      reason: %s\n", m->reason);
	vty_out(vty, "      zebra: %s\n", zapi_lag_mbr_flags2str(m->zflags, buf, sizeof(buf)));
	vty_out(vty, "      detached %" PRIu64 " times, attached %" PRIu64 " times\n",
		m->stats.detach_count, m->stats.attach_count);
	vty_out(vty,
		"      frames: rx %" PRIu64 " (bad %" PRIu64 ", not this LAG %" PRIu64
		", wrong discriminator %" PRIu64 ", no session %" PRIu64 "), tx %" PRIu64
		" (errors %" PRIu64 ")\n",
		m->stats.rx_frames, m->stats.rx_bad_frame, m->stats.rx_mismatch,
		m->stats.rx_wrong_discr, m->stats.rx_no_session, m->stats.tx_frames,
		m->stats.tx_errors);
}

static void lag_show_one(struct vty *vty, struct bfd_lag *lag, json_object *json)
{
	const char *no_session = lag_no_session_reason(lag);
	struct bfd_lag_member *m;
	uint32_t detect = 0;

	frr_each (bfd_lag_members, &lag->members, m) {
		uint32_t d = lag_member_detect_ms(m);

		if (d && (!detect || d < detect))
			detect = d;
	}

	if (json) {
		json_object *jl = json_object_new_object();
		json_object *jmbrs = json_object_new_object();

		json_object_string_add(jl, "vrf", lag_vrf_name(lag));
		json_object_int_add(jl, "ifindex", lag->ifindex);
		json_object_string_add(jl, "status", lag_status_str(lag));
		if (lag->status_known)
			json_object_int_add(jl, "bondMode", lag->bond_mode);
		json_object_string_add(jl, "mode", bfd_lag_mode2str(lag->mode));
		json_object_boolean_add(jl, "adminDown", lag->admin_down);
		json_object_boolean_add(jl, "useIpv4", lag->use_ipv4);
		if (lag->has_dest4)
			json_object_string_addf(jl, "ipv4DestAddr", "%pI4", &lag->dest4);
		if (lag->has_src4)
			json_object_string_addf(jl, "ipv4SourceAddr", "%pI4", &lag->src4);
		if (lag->local4.s_addr != INADDR_ANY)
			json_object_string_addf(jl, "ipv4SourceAddrInUse", "%pI4", &lag->local4);
		if (lag->profile_name)
			json_object_string_add(jl, "profile", lag->profile_name);
		json_object_int_add(jl, "enableGrace", lag->enable_grace);
		json_object_int_add(jl, "holdUp", lag->hold_up);
		json_object_string_add(jl, "noSessionReason", no_session ? no_session : "");
		if (detect && detect < BFD_LAG_MIN_DETECT_WARN)
			json_object_string_addf(jl, "warning",
						"detection time %u ms is below %u ms", detect,
						BFD_LAG_MIN_DETECT_WARN);
		frr_each (bfd_lag_members, &lag->members, m) {
			json_object *jm = json_object_new_object();

			lag_member_show(vty, m, jm);
			json_object_object_add(jmbrs, m->name, jm);
		}
		json_object_object_add(jl, "members", jmbrs);
		json_object_object_add(json, lag->name, jl);
		return;
	}

	vty_out(vty, "lag %s (VRF %s): %s, mode %s%s\n", lag->name, lag_vrf_name(lag),
		lag_status_str(lag), bfd_lag_mode2str(lag->mode),
		lag->admin_down ? ", shutdown" : "");
	vty_out(vty, "  ipv4: destination %pI4, source %pI4%s\n", &lag->dest4, &lag->local4,
		lag->has_src4 ? " (configured)" : "");
	vty_out(vty, "  profile %s, enable-grace %u ms, hold-up %u ms\n",
		lag->profile_name ? lag->profile_name : "-", lag->enable_grace, lag->hold_up);
	if (no_session)
		vty_out(vty, "  no sessions: %s\n", no_session);
	if (detect && detect < BFD_LAG_MIN_DETECT_WARN)
		vty_out(vty,
			"  warning: detection time %u ms is below %u ms; software BFD may see false failures\n",
			detect, BFD_LAG_MIN_DETECT_WARN);
	frr_each (bfd_lag_members, &lag->members, m)
		lag_member_show(vty, m, NULL);
	vty_out(vty, "\n");
}

void bfd_lag_show(struct vty *vty, const char *name, bool use_json)
{
	json_object *json = use_json ? json_object_new_object() : NULL;
	struct bfd_lag *lag;

	frr_each (bfd_lags, &bfd_lags, lag) {
		if (name && strcmp(name, lag->name))
			continue;
		lag_show_one(vty, lag, json);
	}

	if (json)
		vty_json(vty, json);
}

void bfd_lag_session_counts(uint32_t *total, uint32_t *up, uint32_t *down, uint32_t *admin_down)
{
	struct bfd_lag_member *m;
	struct bfd_lag *lag;

	*total = *up = *down = *admin_down = 0;
	frr_each (bfd_lags, &bfd_lags, lag) {
		frr_each (bfd_lag_members, &lag->members, m) {
			if (!m->bs4)
				continue;
			(*total)++;
			if (m->bs4->ses_state == PTM_BFD_UP)
				(*up)++;
			else if (m->bs4->ses_state == PTM_BFD_ADM_DOWN)
				(*admin_down)++;
			else
				(*down)++;
		}
	}
}

void bfd_lag_show_statistics(struct vty *vty, bool use_json)
{
	uint32_t total, up, down, admin_down;

	bfd_lag_session_counts(&total, &up, &down, &admin_down);

	if (use_json) {
		json_object *json = json_object_new_object();
		json_object *js = json_object_new_object();

		/* RFC 9314 micro-bfd-ipv4-session-statistics/summary. */
		json_object_int_add(js, "numberOfSessions", total);
		json_object_int_add(js, "numberOfSessionsUp", up);
		json_object_int_add(js, "numberOfSessionsDown", down);
		json_object_int_add(js, "numberOfSessionsAdminDown", admin_down);
		json_object_object_add(json, "microBfdIpv4SessionStatistics", js);
		vty_json(vty, json);
		return;
	}

	vty_out(vty, "micro-BFD IPv4 sessions: %u (up %u, down %u, admin-down %u)\n", total, up,
		down, admin_down);
}
