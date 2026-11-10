// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 7130 micro-BFD: BFD on LAG (bond) member links.
 *
 * A micro-BFD session runs on every member of a configured bond, one per
 * configured address family (IPv4, IPv6). The member carries the bond's
 * traffic only while its sessions are Up ("strict" mode): when one fails,
 * bfdd asks zebra to take the member out of the bond (detach,
 * ZEBRA_LAG_MBFD_DIST_SET); when they are all Up again, to put it back
 * (attach). Zebra tells bfdd about the bond and its members
 * (ZEBRA_LAG_MBFD_BOND_STATUS / MEMBER_UPDATE) and re-attaches what bfdd
 * detached when bfdd goes away (fail-open).
 *
 * Packets (RFC 7130, Section 2): UDP destination port 6784, IPv4 TTL / IPv6
 * hop limit 255, Ethernet destination 01:00:5e:90:00:01 for both families,
 * source address of the LAG (IPv6: a global one), sent directly on the
 * member link. bfdd sends and reads them on one raw (AF_PACKET) socket per
 * member and family, bound to that member, so a packet is always matched to
 * the member it arrived on, and copies seen on the bond or sent by bfdd
 * itself never reach the session. A classic BPF filter keeps everything but
 * the family's incoming untagged UDP 6784 out of the socket. A UDP socket
 * on port 6784 per VRF and family, never read, keeps the kernel from
 * answering these packets with ICMP port unreachable.
 *
 * Both families configured: a member carries traffic only while both of its
 * sessions are Up. A family that can't run (no source address, ...) is left
 * out of that decision, and so is a family whose peer signals AdminDown.
 *
 * Strict mode, per member:
 * - enable-grace: after its sessions are created (configuration, bfdd
 *   start, a new member), the member is left alone for this long so the
 *   sessions can come Up first.
 * - A session Down: detach at once, unless in enable-grace, settling after
 *   an attach, or the member is protodown.
 * - All sessions Up while detached: wait hold-up, then attach.
 * - Attach bounces the member link (the bonding driver needs it down to
 *   enslave it), so the sessions go Down again on both ends. Down is
 *   ignored until the member distributes with its sessions Up, for at most
 *   BFD_LAG_SETTLE_MAX.
 * - Shutdown, or a peer signalling AdminDown in every family (RFC 5882,
 *   Section 3.2): not a failure, members are attached (fail-open).
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

/* RFC 7130, Section 2.3: dedicated MAC address, both address families. */
static const uint8_t bfd_lag_dmac[ETH_ALEN] = { 0x01, 0x00, 0x5e, 0x90, 0x00, 0x01 };

static void lag_member_evaluate(struct bfd_lag_member *m);
static void lag_sessions_sync(struct bfd_lag *lag);
static void lag_member_sessions_delete(struct bfd_lag_member *m);
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
 * Address family helpers.
 */
static int af_family(enum bfd_lag_af af)
{
	return af == BFD_LAG_AF_IPV6 ? AF_INET6 : AF_INET;
}

static const char *af_name(enum bfd_lag_af af)
{
	return af == BFD_LAG_AF_IPV6 ? "IPv6" : "IPv4";
}

static enum bfd_lag_af af_of_session(const struct bfd_session *bs)
{
	return bs->key.family == AF_INET6 ? BFD_LAG_AF_IPV6 : BFD_LAG_AF_IPV4;
}

static size_t af_addrlen(enum bfd_lag_af af)
{
	return af == BFD_LAG_AF_IPV6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
}

static bool addr_is_zero(enum bfd_lag_af af, const union bfd_lag_addr *a)
{
	static const union bfd_lag_addr zero;

	return memcmp(a, &zero, af_addrlen(af)) == 0;
}

static bool addr_eq(enum bfd_lag_af af, const union bfd_lag_addr *a, const union bfd_lag_addr *b)
{
	return memcmp(a, b, af_addrlen(af)) == 0;
}

static const char *addr2str(enum bfd_lag_af af, const union bfd_lag_addr *a, char *buf, size_t len)
{
	return inet_ntop(af_family(af), a, buf, len) ? buf : "?";
}

static void addr2sa(enum bfd_lag_af af, const union bfd_lag_addr *a, struct sockaddr_any *sa)
{
	memset(sa, 0, sizeof(*sa));
	if (af == BFD_LAG_AF_IPV6) {
		sa->sa_sin6.sin6_family = AF_INET6;
		sa->sa_sin6.sin6_addr = a->v6;
	} else {
		sa->sa_sin.sin_family = AF_INET;
		sa->sa_sin.sin_addr = a->v4;
	}
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

/*
 * The bond's source address for a family: IPv4, the primary (non
 * secondary) address; IPv6, the first global unicast address (RFC 7130,
 * Section 2.1: not link-local).
 */
static union bfd_lag_addr lag_bond_addr(const struct bfd_lag *lag, enum bfd_lag_af af)
{
	union bfd_lag_addr none = {};
	const struct connected *ifc;
	struct interface *ifp;

	if (lag->ifindex == IFINDEX_INTERNAL)
		return none;

	ifp = lag_if_by_index(lag->ifindex, lag->vrf_id);
	if (!ifp)
		return none;

	frr_each (if_connected_const, ifp->connected, ifc) {
		union bfd_lag_addr a = {};

		if (!ifc->address || ifc->address->family != af_family(af))
			continue;

		if (af == BFD_LAG_AF_IPV4) {
			if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY))
				continue;
			a.v4 = ifc->address->u.prefix4;
			return a;
		}

		a.v6 = ifc->address->u.prefix6;
		if (IN6_IS_ADDR_LINKLOCAL(&a.v6) || IN6_IS_ADDR_MULTICAST(&a.v6) ||
		    IN6_IS_ADDR_LOOPBACK(&a.v6) || IN6_IS_ADDR_UNSPECIFIED(&a.v6))
			continue;
		return a;
	}

	return none;
}

bool bfd_lag_member_detached(const struct bfd_lag_member *m)
{
	return CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_MBFD_DETACHED);
}

bool bfd_lag_member_distributing(const struct bfd_lag_member *m)
{
	return CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_DISTRIBUTING);
}

/* Why the LAG runs no sessions at all, whatever the family (NULL: it can). */
static const char *lag_bond_reason(const struct bfd_lag *lag)
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
	if (!bfd_vrf_is_permitted(lag_vrf_name(lag)))
		return "VRF not monitored (--vrfs)";
#ifndef BFD_LINUX
	return "not supported on this platform";
#endif

	return NULL;
}

/* Why a family runs no sessions (NULL: it runs them). */
static const char *lag_af_reason(const struct bfd_lag *lag, enum bfd_lag_af af)
{
	const struct bfd_lag_af_cfg *c = &lag->af[af];
	const char *reason = lag_bond_reason(lag);

	if (reason)
		return reason;
	if (!c->use || !c->has_dest)
		return af == BFD_LAG_AF_IPV6 ? "no IPv6 destination address"
					     : "no IPv4 destination address";
	if (addr_is_zero(af, &c->local))
		return af == BFD_LAG_AF_IPV6 ? "no IPv6 source address" : "no IPv4 source address";

	return NULL;
}

static bool lag_af_runs(const struct bfd_lag *lag, enum bfd_lag_af af)
{
	return lag_af_reason(lag, af) == NULL;
}

/* Why the LAG runs no sessions in any family (NULL: it runs some). */
static const char *lag_no_session_reason(const struct bfd_lag *lag)
{
	const char *reason = lag_bond_reason(lag);

	if (reason)
		return reason;

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		if (lag_af_runs(lag, af))
			return NULL;

	/* Neither runs: the IPv4 reason, unless only IPv6 is configured. */
	if (!lag->af[BFD_LAG_AF_IPV4].use && lag->af[BFD_LAG_AF_IPV6].use)
		return lag_af_reason(lag, BFD_LAG_AF_IPV6);
	return lag_af_reason(lag, BFD_LAG_AF_IPV4);
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
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		m->s[af].m = m;
		m->s[af].af = af;
		m->s[af].port_sock = -1;
	}
	bfd_lag_members_add_tail(&lag->members, m);

	return m;
}

static void lag_member_free(struct bfd_lag_member *m)
{
	lag_member_sessions_delete(m);

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

static bool lag_member_has_session(const struct bfd_lag_member *m)
{
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		if (m->s[af].bs)
			return true;
	return false;
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

static void lag_member_grace_start(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;

	m->in_grace = lag->enable_grace > 0;
	m->holdup_done = false;
	event_cancel(&m->t_grace);
	if (m->in_grace)
		event_add_timer_msec(master, lag_grace_cb, m, lag->enable_grace, &m->t_grace);
}

static void lag_member_session_create(struct bfd_lag_member *m, enum bfd_lag_af af)
{
	struct bfd_lag *lag = m->lag;
	struct bfd_lag_af_cfg *c = &lag->af[af];
	struct bfd_lag_msess *ms = &m->s[af];
	struct sockaddr_any peer, local;
	char bfdname[BFD_NAME_SIZE + 1];
	union bfd_lag_addr none = {};
	struct bfd_session *bs;

	snprintf(bfdname, sizeof(bfdname), "%s%s", BFD_LAG_NAME_PREFIX, lag->name);

	addr2sa(af, &c->dest, &peer);
	addr2sa(af, c->has_src ? &c->src : &none, &local);

	bs = bfd_session_new(BFD_MODE_TYPE_MICRO_BFD);
	gen_bfd_key(&bs->key, &peer, &local, false, m->name, lag_vrf_name(lag), bfdname);
	strlcpy(bs->bfd_name, bfdname, sizeof(bs->bfd_name));
	if (af == BFD_LAG_AF_IPV6)
		SET_FLAG(bs->flags, BFD_SESS_FLAG_IPV6);
	bs->lag_mbr = m;
	ms->bs = bs;
	ms->peer_admin_down = false;

	/* Local shutdown before the session starts, profile applied below. */
	bs->peer_profile.admin_shutdown = lag->admin_down;

	if (bfd_key_lookup(&bs->key)) {
		zlog_warn("micro-BFD: lag %s member %s: %s session exists already", lag->name,
			  m->name, af_name(af));
		ms->bs = NULL;
		bs->lag_mbr = NULL;
		bfd_session_free(bs);
		return;
	}

	if (bs_registrate(bs) == NULL) {
		/* bs_registrate() freed it. */
		ms->bs = NULL;
		return;
	}

	if (lag->profile_name)
		bfd_profile_apply(lag->profile_name, bs);
	else
		bfd_session_apply(bs);

	/* Give the new session time to come Up before acting on it. */
	lag_member_grace_start(m);

	LAG_DEBUG("lag %s member %s: session created (%s)", lag->name, m->name, bs_to_string(bs));
}

static void lag_member_session_delete(struct bfd_lag_member *m, enum bfd_lag_af af)
{
	struct bfd_session *bs = m->s[af].bs;

	if (!bs)
		return;

	LAG_DEBUG("lag %s member %s: %s session deleted", m->lag->name, m->name, af_name(af));

	/*
	 * RFC 5880, Section 6.8.16: tell the peer the session goes away
	 * (AdminDown) rather than let it time out, so the peer doesn't take
	 * the member out for it. Twice, in case one is lost.
	 */
	if (bs->sock != -1 && bs->ses_state != PTM_BFD_ADM_DOWN) {
		bs->ses_state = PTM_BFD_ADM_DOWN;
		bs->local_diag = BD_ADMIN_DOWN;
		ptm_bfd_snd(bs, 0);
		ptm_bfd_snd(bs, 0);
	}

	/* bfd_session_free() unlinks it through bfd_lag_session_freed(). */
	bfd_session_free(bs);
	m->s[af].bs = NULL;
	m->s[af].peer_admin_down = false;

	if (!lag_member_has_session(m)) {
		m->in_grace = false;
		m->holdup_done = false;
		event_cancel(&m->t_grace);
		event_cancel(&m->t_holdup);
	}
}

static void lag_member_sessions_delete(struct bfd_lag_member *m)
{
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		lag_member_session_delete(m, af);
}

/* The source address of a family: configured, or the bond's. */
static void lag_local_update(struct bfd_lag *lag, enum bfd_lag_af af)
{
	struct bfd_lag_af_cfg *c = &lag->af[af];
	union bfd_lag_addr now;

	if (c->has_src) {
		c->local = c->src;
		return;
	}

	/* Losing an address is lag_addr_update()'s decision. */
	now = lag_bond_addr(lag, af);
	if (!addr_is_zero(af, &now))
		c->local = now;
}

/* A configured family that can't run, while the LAG could run it. */
static const char *lag_af_blocked(const struct bfd_lag *lag, enum bfd_lag_af af)
{
	const struct bfd_lag_af_cfg *c = &lag->af[af];

	if (!c->use || !c->has_dest || lag_bond_reason(lag))
		return NULL;
	return lag_af_reason(lag, af);
}

/*
 * A3: a configured family that can't run is left out of the decision. Say
 * so once, if it still can't a moment later: at startup the bond's
 * addresses come after the bond.
 */
static void lag_warn_cb(struct event *t)
{
	struct bfd_lag *lag = EVENT_ARG(t);

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		struct bfd_lag_af_cfg *c = &lag->af[af];
		const char *reason = lag_af_blocked(lag, af);

		if (!reason || c->warned)
			continue;
		zlog_warn("micro-BFD: lag %s: %s sessions can't run (%s); members are judged without them",
			  lag->name, af_name(af), reason);
		c->warned = true;
	}
}

/* Create or delete the sessions of a LAG as the configuration allows. */
static void lag_sessions_sync(struct bfd_lag *lag)
{
	struct bfd_lag_member *m;
	bool runs[BFD_LAG_AF_MAX];

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		struct bfd_lag_af_cfg *c = &lag->af[af];

		lag_local_update(lag, af);
		runs[af] = lag_af_runs(lag, af);

		if (!lag_af_blocked(lag, af))
			c->warned = false;
		else if (!c->warned && !event_is_scheduled(lag->t_warn))
			event_add_timer_msec(master, lag_warn_cb, lag, BFD_LAG_ADDR_CHECK,
					     &lag->t_warn);
	}

	frr_each (bfd_lag_members, &lag->members, m) {
		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
			if (runs[af] && !m->s[af].bs)
				lag_member_session_create(m, af);
			else if (!runs[af] && m->s[af].bs)
				lag_member_session_delete(m, af);
		}
		lag_member_evaluate(m);
	}
}

/*
 * Delete the sessions of a family before its addresses change: the
 * AdminDown they send on the way out must carry the addresses the peer
 * knows them by. lag_sessions_sync() creates them again.
 */
static void lag_af_sessions_delete(struct bfd_lag *lag, enum bfd_lag_af af)
{
	struct bfd_lag_member *m;

	frr_each (bfd_lag_members, &lag->members, m)
		lag_member_session_delete(m, af);
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
static struct sock_filter bfd_lag_bpf4[] = {
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

/*
 * Incoming untagged IPv6 with UDP as the first next header (no extension
 * headers), to port 6784, hop limit 255, not sent by us, addressed to us.
 */
static struct sock_filter bfd_lag_bpf6[] = {
	/* 0: packet type: drop our own and other hosts' frames. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE),
	/* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_OUTGOING, 12, 0),
	/* 2 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_OTHERHOST, 11, 0),
	/* 3: VLAN tag the NIC took off. */
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT),
	/* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 9),
	/* 5: ethertype IPv6. */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
	/* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 0, 7),
	/* 7: next header UDP. */
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 20),
	/* 8 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 5),
	/* 9: UDP destination port (14 + 40 + 2). */
	BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 56),
	/* 10 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BFD_LAG_PORT, 0, 3),
	/* 11: hop limit 255 (RFC 5881, Section 5). */
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 21),
	/* 12 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 255, 0, 1),
	/* 13: accept. */
	BPF_STMT(BPF_RET | BPF_K, 0xffff),
	/* 14: drop. */
	BPF_STMT(BPF_RET | BPF_K, 0),
};

static int lag_raw_socket(const struct bfd_lag_member *m, enum bfd_lag_af af, const struct vrf *vrf)
{
	struct sock_fprog prog = {};
	struct packet_mreq mreq = {};
	struct sockaddr_ll sll = {};
	int sd;

	if (af == BFD_LAG_AF_IPV6) {
		prog.len = array_size(bfd_lag_bpf6);
		prog.filter = bfd_lag_bpf6;
	} else {
		prog.len = array_size(bfd_lag_bpf4);
		prog.filter = bfd_lag_bpf4;
	}

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
 * to it keeps it from other sessions (micro-BFD or not) of the same family
 * for as long as the session runs.
 */
static int lag_port_reserve(struct bfd_lag_msess *ms, const struct vrf *vrf)
{
	struct sockaddr_storage ss = {};
	socklen_t slen;
	int sd, family = af_family(ms->af);

	frr_with_privs (&bglobal.bfdd_privs) {
		sd = vrf_socket(family, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id, NULL);
	}
	if (sd < 0)
		return -1;

	if (family == AF_INET6) {
		int on = 1;

		setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		slen = sizeof(struct sockaddr_in6);
	} else {
		slen = sizeof(struct sockaddr_in);
	}
	ss.ss_family = family;

	if (bp_bind_src_port(sd, (struct sockaddr *)&ss, slen) < 0 ||
	    getsockname(sd, (struct sockaddr *)&ss, &slen) < 0) {
		close(sd);
		return -1;
	}

	ms->port_sock = sd;
	ms->sport = ntohs(family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
					     : ((struct sockaddr_in *)&ss)->sin_port);
	return 0;
}

/* The per VRF and family port 6784 sink (see bfd.h, bg_mbfd). */
static void lag_sink_ref(struct vrf *vrf, enum bfd_lag_af af)
{
	struct bfd_vrf_global *bvrf = vrf->info;
	struct sockaddr_storage ss = {};
	int *sdp, sd, one = 1, family = af_family(af);
	unsigned int *count;
	socklen_t slen;

	if (!bvrf)
		return;
	sdp = af == BFD_LAG_AF_IPV6 ? &bvrf->bg_mbfd6 : &bvrf->bg_mbfd;
	count = af == BFD_LAG_AF_IPV6 ? &bvrf->bg_mbfd6_count : &bvrf->bg_mbfd_count;
	if ((*count)++ > 0 || *sdp != -1)
		return;

	frr_with_privs (&bglobal.bfdd_privs) {
		sd = vrf_socket(family, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id, vrf->name);
	}
	if (sd < 0) {
		zlog_warn("micro-BFD: VRF %s: %s UDP %d socket: %s", vrf->name, af_name(af),
			  BFD_LAG_PORT, safe_strerror(errno));
		return;
	}

	/* Never read; keep its queue small. */
	setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &one, sizeof(one));
	if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;

		setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(BFD_LAG_PORT);
		slen = sizeof(*sin6);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;

		sin->sin_family = AF_INET;
		sin->sin_port = htons(BFD_LAG_PORT);
		slen = sizeof(*sin);
	}
	if (bind(sd, (struct sockaddr *)&ss, slen) < 0) {
		zlog_warn("micro-BFD: VRF %s: bind %s UDP %d: %s", vrf->name, af_name(af),
			  BFD_LAG_PORT, safe_strerror(errno));
		close(sd);
		return;
	}

	*sdp = sd;
}

static void lag_sink_unref(struct vrf *vrf, enum bfd_lag_af af)
{
	struct bfd_vrf_global *bvrf = vrf ? vrf->info : NULL;
	unsigned int *count;
	int *sdp;

	if (!bvrf)
		return;
	sdp = af == BFD_LAG_AF_IPV6 ? &bvrf->bg_mbfd6 : &bvrf->bg_mbfd;
	count = af == BFD_LAG_AF_IPV6 ? &bvrf->bg_mbfd6_count : &bvrf->bg_mbfd_count;
	if (*count == 0 || --(*count) > 0)
		return;

	if (*sdp != -1) {
		close(*sdp);
		*sdp = -1;
	}
}
#endif /* BFD_LINUX */

void bfd_lag_vrf_disable(struct bfd_vrf_global *bvrf)
{
	if (bvrf->bg_mbfd != -1) {
		close(bvrf->bg_mbfd);
		bvrf->bg_mbfd = -1;
	}
	if (bvrf->bg_mbfd6 != -1) {
		close(bvrf->bg_mbfd6);
		bvrf->bg_mbfd6 = -1;
	}
	bvrf->bg_mbfd_count = 0;
	bvrf->bg_mbfd6_count = 0;
}

#ifdef BFD_LINUX
static void lag_recv_cb(struct event *t);
#endif

static void lag_msess_close(struct bfd_lag_msess *ms)
{
	event_cancel(&ms->t_read);
	if (ms->port_sock != -1) {
		close(ms->port_sock);
		ms->port_sock = -1;
	}
}

int bfd_lag_session_enable(struct bfd_session *bs)
{
#ifdef BFD_LINUX
	struct bfd_lag_member *m = bs->lag_mbr;
	enum bfd_lag_af af = af_of_session(bs);
	struct bfd_lag_msess *ms;
	struct interface *ifp;
	struct vrf *vrf;
	int sd;

	if (!m)
		return 0;
	ms = &m->s[af];

	vrf = vrf_lookup_by_id(m->lag->vrf_id);
	if (!vrf || !vrf->info)
		return 0;

	ifp = lag_if_by_index(m->ifindex, vrf->vrf_id);
	if (!ifp)
		return 0;

	if (addr_is_zero(af, &m->lag->af[af].local))
		return 0;

	if (bs->sock != -1)
		return 0;

	if (ms->port_sock == -1 && lag_port_reserve(ms, vrf) < 0) {
		zlog_warn("micro-BFD: member %s: no %s source port available", m->name,
			  af_name(af));
		return 0;
	}

	sd = lag_raw_socket(m, af, vrf);
	if (sd < 0) {
		close(ms->port_sock);
		ms->port_sock = -1;
		return 0;
	}

	bs->vrf = vrf;
	bs->ifp = ifp;
	bs->sock = sd;
	addr2sa(af, &m->lag->af[af].local, &bs->local_address);

	lag_sink_ref(vrf, af);
	event_add_read(master, lag_recv_cb, ms, sd, &ms->t_read);

	/* Micro-BFD is never passive: start right away. */
	bfd_recvtimer_update(bs);
	ptm_bfd_start_xmt_timer(bs, false);
	bfd_rtt_init(bs);

	LAG_DEBUG("member %s: %s session enabled, source port %u", m->name, af_name(af), ms->sport);
#endif /* BFD_LINUX */
	return 0;
}

void bfd_lag_session_disable(struct bfd_session *bs)
{
	struct bfd_lag_member *m = bs->lag_mbr;

	if (m)
		lag_msess_close(&m->s[af_of_session(bs)]);

	if (bs->sock != -1) {
#ifdef BFD_LINUX
		lag_sink_unref(bs->vrf, af_of_session(bs));
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
		struct bfd_lag_msess *ms = &m->s[af_of_session(bs)];

		if (ms->bs == bs)
			ms->bs = NULL;
		lag_msess_close(ms);
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
	enum bfd_lag_af af;
	struct bfd_lag_af_cfg *c;
	ssize_t flen;

	if (!m || bs->sock == -1)
		return -1;
	af = af_of_session(bs);
	c = &m->lag->af[af];

	fp.family = af_family(af);
	/* The member's own (current) MAC: the bond's while it's attached. */
	memcpy(fp.smac, m->mac, ETH_ALEN);
	if (bs->ifp && !memcmp(fp.smac, "\0\0\0\0\0\0", ETH_ALEN) &&
	    bs->ifp->hw_addr_len == ETH_ALEN)
		memcpy(fp.smac, bs->ifp->hw_addr, ETH_ALEN);
	memcpy(fp.dmac, bfd_lag_dmac, ETH_ALEN);
	if (af == BFD_LAG_AF_IPV6) {
		fp.src.v6 = c->local.v6;
		fp.dst.v6 = c->dest.v6;
	} else {
		fp.src.v4 = c->local.v4;
		fp.dst.v4 = c->dest.v4;
	}
	fp.sport = m->s[af].sport;
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
	sll.sll_protocol = htons(af == BFD_LAG_AF_IPV6 ? ETH_P_IPV6 : ETH_P_IP);
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
	struct bfd_lag_msess *ms = EVENT_ARG(t);
	struct bfd_lag_member *m = ms->m;
	enum bfd_lag_af af = ms->af;
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
	struct bfd_lag_af_cfg *c;
	union bfd_lag_addr src = {}, dst = {};
	ssize_t n;
	int rv;

	event_add_read(master, lag_recv_cb, ms, sd, &ms->t_read);

	n = recvfrom(sd, frame, sizeof(frame), 0, (struct sockaddr *)&sll, &slen);
	if (n < 0) {
		if (!ERRNO_IO_RETRY(errno) && bglobal.debug_network)
			zlog_debug("micro-BFD: member %s: recv: %s", m->name, safe_strerror(errno));
		return;
	}

	m->stats.rx_frames++;
	c = &m->lag->af[af];

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

	if (fi.family == AF_INET6) {
		src.v6 = fi.src.v6;
		dst.v6 = fi.dst.v6;
	} else {
		src.v4 = fi.src.v4;
		dst.v4 = fi.dst.v4;
	}

	/* The LAG's addresses, both ways (RFC 7130, Section 2.1). */
	if (fi.family != af_family(af) || fi.dport != BFD_LAG_PORT ||
	    !addr_eq(af, &src, &c->dest) || !addr_eq(af, &dst, &c->local)) {
		char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];

		m->stats.rx_mismatch++;
		if (bglobal.debug_network)
			zlog_debug("micro-BFD: member %s: dropped packet %s -> %s port %u: not this LAG's",
				   m->name, addr2str(af, &src, sbuf, sizeof(sbuf)),
				   addr2str(af, &dst, dbuf, sizeof(dbuf)), fi.dport);
		return;
	}

	if (fi.plen < BFD_PKT_LEN || fi.plen > sizeof(pkt.buf)) {
		m->stats.rx_bad_frame++;
		return;
	}

	bs = ms->bs;
	if (!bs) {
		m->stats.rx_no_session++;
		return;
	}

	/* Aligned copy of the BFD packet. */
	memcpy(pkt.buf, fi.payload, fi.plen);

	/*
	 * The session on this member and family is the only one this packet
	 * can be for: a Your Discriminator of any other session is refused,
	 * even one of the same LAG on another member.
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
	rx.vrfid = bs->vrf ? bs->vrf->vrf_id : m->lag->vrf_id;
	addr2sa(af, &src, &rx.peer);
	addr2sa(af, &dst, &rx.local);
	if (af == BFD_LAG_AF_IPV6) {
		rx.peer.sa_sin6.sin6_port = htons(fi.sport);
		rx.local.sa_sin6.sin6_port = htons(fi.dport);
	} else {
		rx.peer.sa_sin.sin_port = htons(fi.sport);
		rx.local.sa_sin.sin_port = htons(fi.dport);
	}

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
static bool lag_session_auth_broken(const struct bfd_session *bs)
{
	return bs && bs->kc && !bfd_keychain_key_find_active(bs->kc, bs->auth_meticulous);
}

/* Down reason of the deciding sessions that are not Up. */
static const char *lag_down_reason(const struct bfd_lag_member *m, const bool *deciding)
{
	bool v4 = false, v6 = false;

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		const struct bfd_session *bs = m->s[af].bs;

		if (!deciding[af] || bs->ses_state == PTM_BFD_UP)
			continue;
		if (lag_session_auth_broken(bs))
			return "auth: no usable key";
		if (af == BFD_LAG_AF_IPV6)
			v6 = true;
		else
			v4 = true;
	}

	/* Name the family only when both decide. */
	if (deciding[BFD_LAG_AF_IPV4] && deciding[BFD_LAG_AF_IPV6]) {
		if (v4 && v6)
			return "session down";
		if (v6)
			return "IPv6 session down";
		return "IPv4 session down";
	}
	return "session down";
}

/*
 * Decide whether the member should carry traffic, and ask zebra for the
 * change. Called on every event that could change the answer.
 */
static void lag_member_evaluate(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;
	bool detached = bfd_lag_member_detached(m);
	bool deciding[BFD_LAG_AF_MAX] = {};
	bool any = false, all_up = true, shut = false, peer_admin = false;
	const char *fail_open = NULL;

	if (!lag->registered || lag->ifindex == IFINDEX_INTERNAL)
		return;

	/* Wait for the kernel, and for zebra to answer the last request. */
	if (CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PENDING) || m->req_outstanding)
		return;

	/*
	 * The sessions that decide: running, not shut down, and whose peer
	 * doesn't signal AdminDown. All of them must be Up (A1).
	 */
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		const struct bfd_lag_msess *ms = &m->s[af];

		if (!ms->bs)
			continue;
		if (ms->bs->ses_state == PTM_BFD_ADM_DOWN) {
			shut = true;
			continue;
		}
		if (ms->peer_admin_down && ms->bs->ses_state != PTM_BFD_UP) {
			peer_admin = true;
			continue;
		}
		deciding[af] = true;
		any = true;
		if (ms->bs->ses_state != PTM_BFD_UP)
			all_up = false;
	}

	/* Not a failure: don't keep members out (fail-open). */
	if (!any) {
		if (shut)
			fail_open = "shutdown";
		else if (peer_admin)
			fail_open = "peer signalled AdminDown";
		else
			fail_open = lag_no_session_reason(lag);
		if (!fail_open)
			fail_open = "no session";
	}

	if (fail_open) {
		m->reason = fail_open;
		m->settling = false;
		event_cancel(&m->t_settle);
		event_cancel(&m->t_holdup);
		if (detached)
			lag_member_request(m, true, fail_open);
		return;
	}

	if (all_up) {
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
			if (!bfd_lag_member_distributing(m)) {
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

	/* A deciding session is not Up. */
	m->holdup_done = false;
	event_cancel(&m->t_holdup);

	if (detached) {
		m->reason = lag_down_reason(m, deciding);
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

	m->reason = lag_down_reason(m, deciding);
	lag_member_request(m, false, m->reason);
}

void bfd_lag_session_notify(struct bfd_session *bs, uint8_t state)
{
	struct bfd_lag_member *m = bs->lag_mbr;
	struct bfd_lag_msess *ms;

	if (!m)
		return;
	ms = &m->s[af_of_session(bs)];

	switch (state) {
	case PTM_BFD_UP:
		ms->peer_admin_down = false;
		break;
	case PTM_BFD_ADM_DOWN:
		/* Local shutdown has the session AdminDown itself. */
		if (bs->ses_state != PTM_BFD_ADM_DOWN)
			ms->peer_admin_down = true;
		break;
	default:
		ms->peer_admin_down = false;
		break;
	}

	LAG_DEBUG("lag %s member %s: %s session %s%s", m->lag->name, m->name,
		  af_name(af_of_session(bs)), state_list[bs->ses_state].str,
		  ms->peer_admin_down ? " (peer AdminDown)" : "");

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
				   bfd_lag_member_detached(m) != m->req_attach)) {
		m->req_outstanding = false;
		event_cancel(&m->t_req);
	}

	if (changed_mac && lag_member_has_session(m))
		LAG_DEBUG("lag %s member %s: MAC now %pEA", lag->name, m->name,
			  (struct ethaddr *)m->mac);

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		if (!m->s[af].bs && lag_af_runs(lag, af))
			lag_member_session_create(m, af);

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
 * The bond's source addresses changed, or may have.
 *
 * Zebra withdraws the addresses of an interface that goes operationally
 * down, and a bond does when micro-BFD took all its members out; it sends
 * them again when the bond comes up. The addresses are still there all
 * along, and the sessions that bring the members back need them. So an
 * address that disappears is only given up when it is still gone a moment
 * later with the bond up. A new or different address is taken at once.
 */
static void lag_addr_update(struct bfd_lag *lag, bool confirm)
{
	struct interface *ifp;
	bool recheck = false;

	if (lag->ifindex == IFINDEX_INTERNAL)
		return;
	ifp = lag_if_by_index(lag->ifindex, lag->vrf_id);

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		struct bfd_lag_af_cfg *c = &lag->af[af];
		char obuf[INET6_ADDRSTRLEN], nbuf[INET6_ADDRSTRLEN];
		union bfd_lag_addr old = c->local, now;

		if (c->has_src)
			continue;

		now = lag_bond_addr(lag, af);
		if (addr_is_zero(af, &now) && !addr_is_zero(af, &old) &&
		    (!confirm || !ifp || !if_is_operative(ifp))) {
			recheck = true;
			continue;
		}
		if (addr_eq(af, &old, &now))
			continue;

		zlog_info("micro-BFD: lag %s: %s source address %s -> %s", lag->name, af_name(af),
			  addr2str(af, &old, obuf, sizeof(obuf)),
			  addr2str(af, &now, nbuf, sizeof(nbuf)));
		/* New address: sockets and packets need it. */
		lag_af_sessions_delete(lag, af);
		c->local = now;
		lag_sessions_sync(lag);
	}

	if (recheck) {
		if (!event_is_scheduled(lag->t_addr))
			event_add_timer_msec(master, lag_addr_check_cb, lag, BFD_LAG_ADDR_CHECK,
					     &lag->t_addr);
	} else {
		event_cancel(&lag->t_addr);
	}
}

static void lag_addr_check_cb(struct event *t)
{
	struct bfd_lag *lag = EVENT_ARG(t);
	struct interface *ifp;

	ifp = lag->ifindex != IFINDEX_INTERNAL ? lag_if_by_index(lag->ifindex, lag->vrf_id) : NULL;

	/* Still down: keep the addresses and look again later. */
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
	event_cancel(&lag->t_warn);
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

void bfd_lag_set_use(struct bfd_lag *lag, enum bfd_lag_af af, bool use)
{
	lag->af[af].use = use;
}

void bfd_lag_set_dest(struct bfd_lag *lag, enum bfd_lag_af af, const union bfd_lag_addr *addr)
{
	struct bfd_lag_af_cfg *c = &lag->af[af];
	bool has = addr != NULL;

	if (has == c->has_dest && (!has || addr_eq(af, addr, &c->dest)))
		return;

	lag_af_sessions_delete(lag, af);
	c->has_dest = has;
	memset(&c->dest, 0, sizeof(c->dest));
	if (has)
		memcpy(&c->dest, addr, af_addrlen(af));
	lag_sessions_sync(lag);
}

void bfd_lag_set_source(struct bfd_lag *lag, enum bfd_lag_af af, const union bfd_lag_addr *addr)
{
	struct bfd_lag_af_cfg *c = &lag->af[af];
	bool has = addr != NULL;

	if (has == c->has_src && (!has || addr_eq(af, addr, &c->src)))
		return;

	lag_af_sessions_delete(lag, af);
	c->has_src = has;
	memset(&c->src, 0, sizeof(c->src));
	if (has)
		memcpy(&c->src, addr, af_addrlen(af));
	/* Back to the bond's address: pick it again. */
	memset(&c->local, 0, sizeof(c->local));
	lag_sessions_sync(lag);
}

void bfd_lag_set_admin_down(struct bfd_lag *lag, bool admin_down)
{
	struct bfd_lag_member *m;

	lag->admin_down = admin_down;

	frr_each (bfd_lag_members, &lag->members, m) {
		/* Back from shutdown: give the sessions time again. */
		if (!admin_down && lag_member_has_session(m))
			lag_member_grace_start(m);

		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
			struct bfd_session *bs = m->s[af].bs;

			if (!bs)
				continue;
			bs->peer_profile.admin_shutdown = admin_down;
			bfd_session_apply(bs);
		}
	}
}

void bfd_lag_set_profile(struct bfd_lag *lag, const char *profile)
{
	struct bfd_lag_member *m;

	XFREE(MTYPE_BFDD_LAG_PROFILE, lag->profile_name);
	if (profile)
		lag->profile_name = XSTRDUP(MTYPE_BFDD_LAG_PROFILE, profile);

	frr_each (bfd_lag_members, &lag->members, m) {
		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
			struct bfd_session *bs = m->s[af].bs;

			if (!bs)
				continue;
			if (profile)
				bfd_profile_apply(profile, bs);
			else
				bfd_profile_remove(bs);
		}
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

/* Members running at least one session, in member order. */
const struct bfd_lag_member *bfd_lag_member_next(const struct bfd_lag *lag,
						 const struct bfd_lag_member *m)
{
	if (!lag)
		return NULL;

	m = m ? bfd_lag_members_const_next(&lag->members, m)
	      : bfd_lag_members_const_first(&lag->members);
	for (; m; m = bfd_lag_members_const_next(&lag->members, m))
		if (lag_member_has_session(m))
			return m;

	return NULL;
}

const struct bfd_lag_member *bfd_lag_member_find(const struct bfd_lag *lag, const char *ifname)
{
	const struct bfd_lag_member *m;

	if (!lag)
		return NULL;

	frr_each (bfd_lag_members_const, &lag->members, m)
		if (lag_member_has_session(m) && strcmp(m->name, ifname) == 0)
			return m;

	return NULL;
}

const struct bfd_session *bfd_lag_member_session(const struct bfd_lag_member *m, enum bfd_lag_af af)
{
	return m->s[af].bs;
}

void bfd_lag_session_counts(enum bfd_lag_af af, uint32_t *total, uint32_t *up, uint32_t *down,
			    uint32_t *admin_down)
{
	struct bfd_lag_member *m;
	struct bfd_lag *lag;

	*total = *up = *down = *admin_down = 0;
	frr_each (bfd_lags, &bfd_lags, lag) {
		frr_each (bfd_lag_members, &lag->members, m) {
			struct bfd_session *bs = m->s[af].bs;

			if (!bs)
				continue;
			(*total)++;
			if (bs->ses_state == PTM_BFD_UP)
				(*up)++;
			else if (bs->ses_state == PTM_BFD_ADM_DOWN)
				(*admin_down)++;
			else
				(*down)++;
		}
	}
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
static uint32_t lag_session_detect_ms(const struct bfd_session *bs)
{
	if (!bs)
		return 0;

	return bs->detect_mult * MAX(bs->timers.required_min_rx, bs->timers.desired_min_tx) / 1000;
}

static json_object *lag_session_json(const struct bfd_lag_msess *ms)
{
	const struct bfd_session *bs = ms->bs;
	json_object *js = json_object_new_object();

	/* RFC 9314 session-running names. */
	json_object_string_add(js, "localState", state_list[bs->ses_state].str);
	json_object_string_add(js, "remoteState", state_list[bs->remote_ses_state].str);
	json_object_string_add(js, "localDiagnostic", diag2str(bs->local_diag));
	json_object_string_add(js, "remoteDiagnostic", diag2str(bs->remote_diag));
	json_object_int_add(js, "localDiscriminator", bs->discrs.my_discr);
	json_object_int_add(js, "remoteDiscriminator", bs->discrs.remote_discr);
	json_object_int_add(js, "localMultiplier", bs->detect_mult);
	json_object_int_add(js, "remoteMultiplier", bs->remote_detect_mult);
	json_object_int_add(js, "desiredMinTxInterval", bs->timers.desired_min_tx / 1000);
	json_object_int_add(js, "requiredMinRxInterval", bs->timers.required_min_rx / 1000);
	json_object_int_add(js, "negotiatedTxInterval", bs->cur_timers.desired_min_tx / 1000);
	json_object_int_add(js, "negotiatedRxInterval", bs->cur_timers.required_min_rx / 1000);
	json_object_int_add(js, "detectionTime", bs->detect_TO / 1000);
	json_object_int_add(js, "sourcePort", ms->sport);
	json_object_boolean_add(js, "peerAdminDown", ms->peer_admin_down);
	json_object_int_add(js, "sessionUpCount", bs->stats.session_up);
	json_object_int_add(js, "sessionDownCount", bs->stats.session_down);
	json_object_int_add(js, "controlPacketInputCount", bs->stats.rx_ctrl_pkt);
	json_object_int_add(js, "controlPacketInputCountBad", bs->stats.rx_bad_ctrl_pkt);
	json_object_int_add(js, "controlPacketOutputCount", bs->stats.tx_ctrl_pkt);

	return js;
}

static void lag_member_show(struct vty *vty, struct bfd_lag_member *m, json_object *jm)
{
	bool detached = bfd_lag_member_detached(m);
	bool distributing = bfd_lag_member_distributing(m);
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
		json_object_string_add(jm, "reason", m->reason ? m->reason : "");
		json_object_boolean_add(jm, "enableGrace", m->in_grace);
		json_object_boolean_add(jm, "settling", m->settling);
		json_object_boolean_add(jm, "peerAdminDown",
					m->s[BFD_LAG_AF_IPV4].peer_admin_down ||
						m->s[BFD_LAG_AF_IPV6].peer_admin_down);
		json_object_int_add(jm, "detachCount", m->stats.detach_count);
		json_object_int_add(jm, "attachCount", m->stats.attach_count);
		json_object_int_add(jm, "rxFrames", m->stats.rx_frames);
		json_object_int_add(jm, "rxBadFrame", m->stats.rx_bad_frame);
		json_object_int_add(jm, "rxMismatch", m->stats.rx_mismatch);
		json_object_int_add(jm, "rxWrongDiscriminator", m->stats.rx_wrong_discr);
		json_object_int_add(jm, "rxNoSession", m->stats.rx_no_session);
		json_object_int_add(jm, "txFrames", m->stats.tx_frames);
		json_object_int_add(jm, "txErrors", m->stats.tx_errors);
		if (m->s[BFD_LAG_AF_IPV4].bs)
			json_object_object_add(jm, "microBfdIpv4",
					       lag_session_json(&m->s[BFD_LAG_AF_IPV4]));
		if (m->s[BFD_LAG_AF_IPV6].bs)
			json_object_object_add(jm, "microBfdIpv6",
					       lag_session_json(&m->s[BFD_LAG_AF_IPV6]));
		return;
	}

	vty_out(vty, "    member %s: %s%s\n", m->name, detached ? "detached" : "attached",
		distributing ? ", distributing" : "");
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		const struct bfd_lag_msess *ms = &m->s[af];
		const struct bfd_session *bs = ms->bs;

		if (!bs)
			continue;
		vty_out(vty,
			"      %s session: %s, discriminator local %u remote %u (%s), multiplier %u/%u, detection %u ms, source port %u%s\n",
			af_name(af), state_list[bs->ses_state].str, bs->discrs.my_discr,
			bs->discrs.remote_discr, state_list[bs->remote_ses_state].str,
			bs->detect_mult, bs->remote_detect_mult, (uint32_t)(bs->detect_TO / 1000),
			ms->sport, ms->peer_admin_down ? ", peer AdminDown" : "");
		vty_out(vty, "        diagnostics: local %s, remote %s\n",
			diag2str(bs->local_diag), diag2str(bs->remote_diag));
	}
	if (!lag_member_has_session(m))
		vty_out(vty, "      no session\n");
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
	char buf[INET6_ADDRSTRLEN];

	frr_each (bfd_lag_members, &lag->members, m) {
		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
			uint32_t d = lag_session_detect_ms(m->s[af].bs);

			if (d && (!detect || d < detect))
				detect = d;
		}
	}

	if (json) {
		json_object *jl = json_object_new_object();
		json_object *jmbrs = json_object_new_object();
		static const char *const pfx[BFD_LAG_AF_MAX] = { "ipv4", "ipv6" };
		static const char *const upfx[BFD_LAG_AF_MAX] = { "Ipv4", "Ipv6" };
		char key[48];

		json_object_string_add(jl, "vrf", lag_vrf_name(lag));
		json_object_int_add(jl, "ifindex", lag->ifindex);
		json_object_string_add(jl, "status", lag_status_str(lag));
		if (lag->status_known)
			json_object_int_add(jl, "bondMode", lag->bond_mode);
		json_object_string_add(jl, "mode", bfd_lag_mode2str(lag->mode));
		json_object_boolean_add(jl, "adminDown", lag->admin_down);
		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
			const struct bfd_lag_af_cfg *c = &lag->af[af];
			const char *r = lag_af_reason(lag, af);

			snprintf(key, sizeof(key), "use%s", upfx[af]);
			json_object_boolean_add(jl, key, c->use);
			if (c->has_dest) {
				snprintf(key, sizeof(key), "%sDestAddr", pfx[af]);
				json_object_string_add(jl, key,
						       addr2str(af, &c->dest, buf, sizeof(buf)));
			}
			if (c->has_src) {
				snprintf(key, sizeof(key), "%sSourceAddr", pfx[af]);
				json_object_string_add(jl, key,
						       addr2str(af, &c->src, buf, sizeof(buf)));
			}
			if (!addr_is_zero(af, &c->local)) {
				snprintf(key, sizeof(key), "%sSourceAddrInUse", pfx[af]);
				json_object_string_add(jl, key,
						       addr2str(af, &c->local, buf, sizeof(buf)));
			}
			snprintf(key, sizeof(key), "%sNoSessionReason", pfx[af]);
			json_object_string_add(jl, key, c->use ? (r ? r : "") : "not configured");
		}
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
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		const struct bfd_lag_af_cfg *c = &lag->af[af];
		char sbuf[INET6_ADDRSTRLEN];
		const char *r;

		if (!c->use)
			continue;
		r = lag_af_reason(lag, af);
		vty_out(vty, "  %s: destination %s, source %s%s%s%s\n",
			af == BFD_LAG_AF_IPV6 ? "ipv6" : "ipv4",
			addr2str(af, &c->dest, buf, sizeof(buf)),
			addr2str(af, &c->local, sbuf, sizeof(sbuf)),
			c->has_src ? " (configured)" : "", r ? ", not running: " : "", r ? r : "");
	}
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

void bfd_lag_show_statistics(struct vty *vty, bool use_json)
{
	json_object *json = use_json ? json_object_new_object() : NULL;

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		uint32_t total, up, down, admin_down;

		bfd_lag_session_counts(af, &total, &up, &down, &admin_down);
		if (json) {
			json_object *js = json_object_new_object();

			/* RFC 9314 micro-bfd-ipv4/ipv6-session-statistics/summary. */
			json_object_int_add(js, "numberOfSessions", total);
			json_object_int_add(js, "numberOfSessionsUp", up);
			json_object_int_add(js, "numberOfSessionsDown", down);
			json_object_int_add(js, "numberOfSessionsAdminDown", admin_down);
			json_object_object_add(json,
					       af == BFD_LAG_AF_IPV6
						       ? "microBfdIpv6SessionStatistics"
						       : "microBfdIpv4SessionStatistics",
					       js);
		} else {
			vty_out(vty, "micro-BFD %s sessions: %u (up %u, down %u, admin-down %u)\n",
				af_name(af), total, up, down, admin_down);
		}
	}

	if (json)
		vty_json(vty, json);
}
