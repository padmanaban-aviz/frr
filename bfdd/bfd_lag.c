// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 7130 micro-BFD: BFD on LAG (bond) member links.
 *
 * A micro-BFD session runs on the members of a configured bond, one per
 * configured address family (IPv4, IPv6). When a member's sessions fail,
 * bfdd asks zebra to hold it down (ZEBRA_LAG_MBFD_DIST_SET "detach": zebra
 * sets it administratively down, it stays in the bond); later to release it
 * ("attach": set it up again). Zebra tells bfdd about the bond and its
 * members (ZEBRA_LAG_MBFD_BOND_STATUS / MEMBER_UPDATE) and releases what
 * bfdd holds down when bfdd goes away (fail-open).
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
 * Session lifecycle (RFC 7130, Section 3): a member's sessions run while
 * it is Distributing, or (strict mode) Standby: in sync with LACP in an
 * aggregator that isn't the active one. On a balance-xor bond: while it is
 * in the bond and up. They are deleted, without AdminDown, once it is
 * neither (after BFD_LAG_DIST_STOP_DELAY), and at once when micro-BFD
 * holds it down: a member held down sends nothing. Micro-BFD only holds
 * down a member that is distributing (or standby).
 *
 * Recovery: a member held down runs no sessions, so nothing tells when its
 * link works again. After recovery-probe-time it is set up again on
 * probation: once LACP lets it distribute (BFD_LAG_SETTLE_MAX at most), its
 * sessions start on both ends and get BFD_LAG_SETTLE_UP (strict: at least
 * enable-grace) to come Up. If they don't, it is held down again and the
 * wait doubles, up to recovery-probe-max; it goes back to
 * recovery-probe-time once the member stayed in with its sessions Up for
 * BFD_LAG_PROBE_STABLE.
 *
 * Strict mode, per member:
 * - enable-grace: after its sessions are created (configuration, bfdd
 *   start, the member starting to distribute), the member is left alone
 *   for this long so the sessions can come Up first.
 * - A session Down: hold the member down at once, unless in enable-grace,
 *   settling after a probe, or the member is protodown.
 * - Shutdown, or a peer signalling AdminDown in every family (RFC 5882,
 *   Section 3.2): not a failure, members are released (fail-open). With
 *   admin-down-hold, a family whose peer signals AdminDown is left out of
 *   the decision only that long; then it counts as Down.
 *
 * Distributing-only mode (like bfd-on-distributing-only elsewhere): LACP
 * admits members; micro-BFD only holds down a member whose sessions went
 * Down after being Up, or didn't come Up within max-setup-time (if set) of
 * it starting to distribute. A member may carry traffic before its
 * sessions are Up, which RFC 7130 doesn't allow: strict is the default.
 *
 * failure-mode tells zebra what to do with the members held down when bfdd
 * goes away: release them (open, the default) or keep them down until bfdd
 * is back (closed, for static and balance-xor bonds, where nothing like LACP
 * keeps our side from sending on a member the peer still keeps out).
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
static void lag_setup_cb(struct event *t);
static void lag_probe_cb(struct event *t);
static void lag_sessions_sync(struct bfd_lag *lag);
static void lag_member_sessions_delete(struct bfd_lag_member *m);
static void lag_member_sessions_quiet_delete(struct bfd_lag_member *m);
static void lag_addr_check_cb(struct event *t);
static void lag_addr_update(struct bfd_lag *lag, bool confirm);

#define LAG_DEBUG(fmt, ...)                                                                       \
	do {                                                                                      \
		if (bglobal.debug_lag)                                                            \
			zlog_debug("micro-BFD: " fmt, ##__VA_ARGS__);                             \
	} while (0)

/* Kernel bond mode balance-xor (IFLA_BOND_MODE). */
#define BFD_LAG_KERNEL_BOND_XOR 2

const char *bfd_lag_fail_mode2str(enum bfd_lag_fail_mode mode)
{
	switch (mode) {
	case BFD_LAG_FAIL_OPEN:
		return "open";
	case BFD_LAG_FAIL_CLOSED:
		return "closed";
	}

	return "unknown";
}

const char *bfd_lag_mode2str(enum bfd_lag_mode mode)
{
	switch (mode) {
	case BFD_LAG_MODE_STRICT:
		return "strict";
	case BFD_LAG_MODE_DIST_ONLY:
		return "distributing-only";
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

bool bfd_lag_member_standby(const struct bfd_lag_member *m)
{
	return CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_STANDBY);
}

/* RFC 7130, Section 3: Distributing, or (strict mode) Standby. */
static bool lag_member_eligible(const struct bfd_lag_member *m)
{
	return bfd_lag_member_distributing(m) ||
	       (m->lag->mode == BFD_LAG_MODE_STRICT && bfd_lag_member_standby(m));
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
 * failure-mode open on a balance-xor bond: when bfdd goes away, zebra puts
 * back members a peer may still keep out, and nothing (no LACP) stops our
 * side from sending on them.
 */
static bool lag_fail_mode_risky(const struct bfd_lag *lag)
{
	return lag->fail_mode == BFD_LAG_FAIL_OPEN && lag->status_known &&
	       lag->status == ZAPI_LAG_BOND_OK && lag->bond_mode == BFD_LAG_KERNEL_BOND_XOR;
}

static void lag_fail_mode_check(struct bfd_lag *lag)
{
	if (!lag_fail_mode_risky(lag)) {
		lag->fail_mode_warned = false;
		return;
	}
	if (lag->fail_mode_warned)
		return;
	zlog_warn("micro-BFD: lag %s: failure-mode open on a balance-xor bond: if bfdd stops, members the peer keeps out are put back and can drop traffic; consider failure-mode closed",
		  lag->name);
	lag->fail_mode_warned = true;
}

/*
 * Zebra registration.
 */
/* Some family has a destination: there is something to run. */
static bool lag_configured(const struct bfd_lag *lag)
{
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		if (lag->af[af].use && lag->af[af].has_dest)
			return true;
	return false;
}

/*
 * Register the bond with zebra, once the LAG has a destination to run
 * sessions to. Earlier, members micro-BFD keeps out (failure-mode closed,
 * across a restart) would be put back for having no session, while the
 * configuration is still being entered line by line.
 */
static void lag_register(struct bfd_lag *lag)
{
	if (lag->registered || lag->ifindex == IFINDEX_INTERNAL || !bfdd_zclient_ready() ||
	    !lag_configured(lag))
		return;

	if (bfdd_zclient_lag_register(lag->vrf_id, lag->ifindex, true,
				      lag->fail_mode == BFD_LAG_FAIL_OPEN) != 0) {
		zlog_warn("micro-BFD: lag %s: can't register with zebra", lag->name);
		return;
	}

	lag->registered = true;
	lag->registered_ifindex = lag->ifindex;
	LAG_DEBUG("lag %s: registered bond ifindex %u (fail-%s)", lag->name, lag->ifindex,
		  bfd_lag_fail_mode2str(lag->fail_mode));
}

static void lag_unregister(struct bfd_lag *lag)
{
	if (!lag->registered)
		return;

	if (bfdd_zclient_ready())
		bfdd_zclient_lag_register(lag->vrf_id, lag->registered_ifindex, false, true);

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
		m->s[af].raw_sock = -1;
	}
	bfd_lag_members_add_tail(&lag->members, m);

	return m;
}

static void lag_msess_raw_close(struct bfd_lag_msess *ms);

static void lag_member_free(struct bfd_lag_member *m)
{
	lag_member_sessions_delete(m);
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		lag_msess_raw_close(&m->s[af]);

	event_cancel(&m->t_grace);
	event_cancel(&m->t_settle);
	event_cancel(&m->t_req);
	event_cancel(&m->t_setup);
	event_cancel(&m->t_dist_stop);
	event_cancel(&m->t_probe);
	event_cancel(&m->t_stable);
	event_cancel(&m->t_noses);
	event_cancel(&m->t_admtx);
	event_cancel(&m->t_nbr_wait);

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
	event_cancel(&m->t_grace);
	if (m->in_grace)
		event_add_timer_msec(master, lag_grace_cb, m, lag->enable_grace, &m->t_grace);
}

/*
 * admin-down-hold: how long a family whose peer signals AdminDown stays out
 * of the decision.
 */
static void lag_admin_hold_cb(struct event *t)
{
	struct bfd_lag_msess *ms = EVENT_ARG(t);
	struct bfd_lag_member *m = ms->m;

	ms->admin_hold_expired = true;
	zlog_info("micro-BFD: lag %s member %s: %s peer AdminDown for %u ms, hold over",
		  m->lag->name, m->name, af_name(ms->af), m->lag->admin_down_hold);
	lag_member_evaluate(m);
}

static void lag_admin_hold_stop(struct bfd_lag_msess *ms)
{
	event_cancel(&ms->t_admin_hold);
	ms->admin_hold_expired = false;
}

/*
 * (Re)arm the hold of a session whose peer signals AdminDown, measured
 * from when AdminDown came: a new admin-down-hold applies to a hold
 * already running.
 */
static void lag_admin_hold_arm(struct bfd_lag_msess *ms)
{
	uint32_t hold = ms->m->lag->admin_down_hold;
	int64_t elapsed;

	event_cancel(&ms->t_admin_hold);
	ms->admin_hold_expired = false;
	if (!ms->peer_admin_down || !hold)
		return;

	elapsed = monotime_since(&ms->admin_down_at, NULL) / 1000;
	if (elapsed >= hold) {
		ms->admin_hold_expired = true;
		return;
	}
	event_add_timer_msec(master, lag_admin_hold_cb, ms, hold - elapsed, &ms->t_admin_hold);
}

/* Milliseconds left of a running hold, 0 if none. */
static uint32_t lag_admin_hold_left(const struct bfd_lag_msess *ms)
{
	return ms->t_admin_hold ? event_timer_remain_msec(ms->t_admin_hold) : 0;
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

	/*
	 * strict: give the new session time to come Up before acting on it.
	 * distributing-only has max-setup-time instead.
	 */
	if (lag->mode == BFD_LAG_MODE_STRICT)
		lag_member_grace_start(m);

	LAG_DEBUG("lag %s member %s: session created (%s)", lag->name, m->name, bs_to_string(bs));
}

static void lag_member_session_delete_(struct bfd_lag_member *m, enum bfd_lag_af af,
				       bool admin_down)
{
	struct bfd_session *bs = m->s[af].bs;

	if (!bs)
		return;

	LAG_DEBUG("lag %s member %s: %s session deleted", m->lag->name, m->name, af_name(af));

	/*
	 * RFC 5880, Section 6.8.16: when the configuration removes a session,
	 * tell the peer (AdminDown) rather than let it time out, so the peer
	 * doesn't take the member out for it. Twice, in case one is lost.
	 */
	if (admin_down && bs->sock != -1 && bs->ses_state != PTM_BFD_ADM_DOWN) {
		bs->ses_state = PTM_BFD_ADM_DOWN;
		bs->local_diag = BD_ADMIN_DOWN;
		ptm_bfd_snd(bs, 0);
		ptm_bfd_snd(bs, 0);
	}

	/* bfd_session_free() unlinks it through bfd_lag_session_freed(). */
	bfd_session_free(bs);
	m->s[af].bs = NULL;
	m->s[af].peer_admin_down = false;
	lag_admin_hold_stop(&m->s[af]);

	if (!lag_member_has_session(m)) {
		m->in_grace = false;
		event_cancel(&m->t_grace);
	}
}

static void lag_member_session_delete(struct bfd_lag_member *m, enum bfd_lag_af af)
{
	lag_member_session_delete_(m, af, true);
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

/*
 * RFC 7130, Section 3: whether the member's sessions should run. While it
 * is Distributing (strict: or Standby), and not held down by micro-BFD.
 */
static bool lag_member_wants_sessions(const struct bfd_lag_member *m)
{
	if (bfd_lag_member_detached(m) || (m->req_outstanding && !m->req_attach))
		return false;
	return lag_member_eligible(m);
}

/*
 * distributing-only, max-setup-time: counts while the member distributes
 * with its sessions not yet Up since they started.
 */
static void lag_member_setup_timer(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;

	if (lag->mode != BFD_LAG_MODE_DIST_ONLY || !lag->max_setup || !m->sess_active ||
	    m->ever_up || m->setup_expired || !bfd_lag_member_distributing(m)) {
		event_cancel(&m->t_setup);
		return;
	}
	if (!event_is_scheduled(m->t_setup))
		event_add_timer_msec(master, lag_setup_cb, m, lag->max_setup, &m->t_setup);
}

static void lag_setup_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	m->setup_expired = true;
	zlog_info("micro-BFD: lag %s member %s: sessions not up within max-setup-time %u ms of distributing",
		  m->lag->name, m->name, m->lag->max_setup);
	lag_member_evaluate(m);
}

static void lag_member_sessions_reset(struct bfd_lag_member *m)
{
	m->nbr_wait_done = false;
	event_cancel(&m->t_nbr_wait);
	m->sess_active = false;
	m->ever_up = false;
	m->setup_expired = false;
	event_cancel(&m->t_setup);
	event_cancel(&m->t_dist_stop);
}

/*
 * RFC 7130, Section 3: delete the sessions of a member that is neither
 * Distributing nor Standby, without AdminDown (LACP stopped on the link for
 * the peer too, it deletes its own).
 */
static void lag_member_sessions_quiet_delete(struct bfd_lag_member *m)
{
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		lag_member_session_delete_(m, af, false);
	lag_member_sessions_reset(m);
}

/*
 * Still not distributing after the delay: delete the sessions (RFC 7130,
 * Section 3). Without AdminDown: LACP stopped on the link for the peer too,
 * and AdminDown would make a peer that keeps the member out put it back.
 */
static void lag_dist_stop_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	if (lag_member_wants_sessions(m))
		return;

	if (!m->sess_active && !lag_member_has_session(m))
		return;
	LAG_DEBUG("lag %s member %s: %s, deleting its sessions", m->lag->name, m->name,
		  bfd_lag_member_detached(m) || (m->req_outstanding && !m->req_attach)
			  ? "held down"
			  : "not distributing");
	lag_member_sessions_quiet_delete(m);
	lag_member_evaluate(m);
}

/*
 * shutdown: bfdd stops transmitting on a session it shuts down. A session
 * created while shut down (the member started distributing, after a
 * recovery probe on the peer) would then send nothing, and the peer would
 * take the silence for a failure: send AdminDown every second instead
 * (RFC 5880, Section 6.8.16; RFC 5882, Section 3.2).
 */
static void lag_admtx_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);
	bool any = false;

	if (!m->lag->admin_down)
		return;

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		struct bfd_session *bs = m->s[af].bs;

		if (!bs || bs->ses_state != PTM_BFD_ADM_DOWN || bs->sock == -1)
			continue;
		bs->local_diag = BD_ADMIN_DOWN;
		ptm_bfd_snd(bs, 0);
		any = true;
	}
	if (any)
		event_add_timer_msec(master, lag_admtx_cb, m, BFD_LAG_ADMIN_DOWN_TX, &m->t_admtx);
}

static void lag_member_admtx_update(struct bfd_lag_member *m)
{
	if (!m->lag->admin_down || !lag_member_has_session(m)) {
		event_cancel(&m->t_admtx);
		return;
	}
	if (!event_is_scheduled(m->t_admtx))
		event_add_timer_msec(master, lag_admtx_cb, m, 0, &m->t_admtx);
}

/*
 * Start, keep or stop the member's sessions, per family as the
 * configuration allows and per member as the mode wants.
 */
static void lag_member_sessions_update(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;
	bool start;

	/* Families that can't run have no session, whatever the mode. */
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		if (m->s[af].bs && !lag_af_runs(lag, af))
			lag_member_session_delete(m, af);

	if (!lag_member_wants_sessions(m)) {
		if (m->sess_active && !event_is_scheduled(m->t_dist_stop))
			event_add_timer_msec(master, lag_dist_stop_cb, m, BFD_LAG_DIST_STOP_DELAY,
					     &m->t_dist_stop);
		return;
	}

	event_cancel(&m->t_dist_stop);
	start = !m->sess_active;
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
		if (!m->s[af].bs && lag_af_runs(lag, af))
			lag_member_session_create(m, af);
	if (start) {
		m->sess_active = true;
		m->ever_up = false;
		m->setup_expired = false;
		event_cancel(&m->t_setup);
		LAG_DEBUG("lag %s member %s: sessions started", lag->name, m->name);
	}
	lag_member_setup_timer(m);
	lag_member_admtx_update(m);
}

/* Create or delete the sessions of a LAG as the configuration allows. */
static void lag_sessions_sync(struct bfd_lag *lag)
{
	struct bfd_lag_member *m;

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		struct bfd_lag_af_cfg *c = &lag->af[af];

		lag_local_update(lag, af);

		if (!lag_af_blocked(lag, af))
			c->warned = false;
		else if (!c->warned && !event_is_scheduled(lag->t_warn))
			event_add_timer_msec(master, lag_warn_cb, lag, BFD_LAG_ADDR_CHECK,
					     &lag->t_warn);
	}

	frr_each (bfd_lag_members, &lag->members, m) {
		lag_member_sessions_update(m);
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
	lag_admin_hold_stop(ms);
	if (ms->port_sock != -1) {
		close(ms->port_sock);
		ms->port_sock = -1;
	}
}

static void lag_msess_raw_close(struct bfd_lag_msess *ms)
{
	event_cancel(&ms->t_read);
	if (ms->raw_sock != -1) {
		close(ms->raw_sock);
		ms->raw_sock = -1;
	}
}

#ifdef BFD_LINUX
/*
 * The member's raw socket, opened with its first session and kept until the
 * member goes: opening one joins the micro-BFD MAC and closing it leaves it,
 * and both wait for the kernel's RTNL lock. That lock is held while a NIC
 * changes state, which is exactly when sessions come and go (a member held
 * down, LACP taking one out): bfdd would stall there, and the sessions on
 * the other members with it, long enough for fast timers to expire (seen:
 * 184 ms with mlx5). Kept open, sessions come and go without a system call
 * that waits for it.
 */
static int lag_msess_raw(struct bfd_lag_msess *ms, struct vrf *vrf)
{
	struct bfd_lag_member *m = ms->m;

	if (ms->raw_sock != -1 && (ms->raw_ifindex != m->ifindex || ms->raw_vrf_id != vrf->vrf_id))
		lag_msess_raw_close(ms);
	if (ms->raw_sock == -1) {
		ms->raw_sock = lag_raw_socket(m, ms->af, vrf);
		if (ms->raw_sock == -1)
			return -1;
		ms->raw_ifindex = m->ifindex;
		ms->raw_vrf_id = vrf->vrf_id;
	}
	if (!ms->t_read)
		event_add_read(master, lag_recv_cb, ms, ms->raw_sock, &ms->t_read);
	return ms->raw_sock;
}
#endif /* BFD_LINUX */

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

	sd = lag_msess_raw(ms, vrf);
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

	/* The member keeps the socket (lag_msess_raw()). */
	if (bs->sock != -1) {
#ifdef BFD_LINUX
		lag_sink_unref(bs->vrf, af_of_session(bs));
#endif
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
 * Holding down and releasing members.
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
	LAG_DEBUG("lag %s member %s: settle time over", m->lag->name, m->name);
	/*
	 * Released but LACP never let it distribute: it stays in without
	 * sessions (RFC 7130, Section 3) and carries nothing; when LACP
	 * admits it, it starts its sessions like any member.
	 */
	if (m->probing && !lag_member_eligible(m)) {
		zlog_info("micro-BFD: lag %s member %s: recovery probe: not distributing at the end of the settle time (LACP, or the peer holds its end down)",
			  m->lag->name, m->name);
		m->probing = false;
	}
	lag_member_sessions_update(m);
	lag_member_evaluate(m);
}

/*
 * Recovery probe: a member held down is released again on probation after
 * its probe wait (recovery-probe-time, doubled after each failure up to
 * recovery-probe-max).
 */
static uint32_t lag_probe_wait(const struct bfd_lag_member *m)
{
	return m->probe_wait ? m->probe_wait : m->lag->recovery_probe;
}

static void lag_member_probe_arm(struct bfd_lag_member *m)
{
	int64_t left;

	if (!m->lag->recovery_probe || !bfd_lag_member_detached(m) || m->req_outstanding ||
	    event_is_scheduled(m->t_probe))
		return;

	/* Held down before bfdd (re)started (failure-mode closed): from now. */
	if (!timerisset(&m->held_at))
		monotime(&m->held_at);

	left = (int64_t)lag_probe_wait(m) - monotime_since(&m->held_at, NULL) / 1000;
	event_add_timer_msec(master, lag_probe_cb, m, MAX(left, 0), &m->t_probe);
}

static uint32_t lag_member_probe_left(const struct bfd_lag_member *m)
{
	return m->t_probe ? event_timer_remain_msec(m->t_probe) : 0;
}

static void lag_member_request(struct bfd_lag_member *m, bool attach, const char *why);

static void lag_probe_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	if (!bfd_lag_member_detached(m) || m->req_outstanding ||
	    CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PENDING))
		return;

	zlog_info("micro-BFD: lag %s member %s: held down for %" PRId64
		  " ms, releasing it on probation",
		  m->lag->name, m->name, monotime_since(&m->held_at, NULL) / 1000);
	m->probing = true;
	m->stats.probe_count++;
	lag_member_request(m, true, "recovery probe");
}

/* In with its sessions Up long enough: the next failure starts afresh. */
static void lag_stable_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	if (m->probe_wait)
		LAG_DEBUG("lag %s member %s: stable, recovery probe wait back to %u ms",
			  m->lag->name, m->name, m->lag->recovery_probe);
	m->probe_wait = 0;
}

static void lag_member_request(struct bfd_lag_member *m, bool attach, const char *why)
{
	struct bfd_lag *lag = m->lag;

	if (bfdd_zclient_lag_dist_set(lag->vrf_id, lag->ifindex, m->ifindex, attach) != 0) {
		zlog_warn("micro-BFD: lag %s member %s: can't ask zebra to %s it", lag->name,
			  m->name, attach ? "release" : "hold down");
		return;
	}

	zlog_info("micro-BFD: lag %s member %s: %s, %s", lag->name, m->name, why,
		  attach ? "releasing it" : "holding it down");

	m->req_outstanding = true;
	m->req_attach = attach;
	monotime(&m->last_action);
	event_cancel(&m->t_req);
	event_add_timer_msec(master, lag_req_cb, m, BFD_LAG_REQ_TIMEOUT, &m->t_req);
	event_cancel(&m->t_probe);
	event_cancel(&m->t_stable);
	event_cancel(&m->t_nbr_wait);
	m->nbr_wait_done = false;

	if (attach) {
		m->stats.attach_count++;
		/* LACP negotiates again before the sessions can start. */
		m->settling = true;
		m->settle_dist = false;
		event_cancel(&m->t_settle);
		event_add_timer_msec(master, lag_settle_cb, m, BFD_LAG_SETTLE_MAX, &m->t_settle);
		return;
	}

	m->stats.detach_count++;
	m->settling = false;
	m->probing = false;
	event_cancel(&m->t_settle);
	/*
	 * Next probe: recovery-probe-time after a failure on a stable member,
	 * twice the last wait otherwise (a failed probe, or a failure soon
	 * after one succeeded), up to recovery-probe-max.
	 */
	if (!m->probe_wait)
		m->probe_wait = lag->recovery_probe;
	else
		m->probe_wait = MIN((uint64_t)m->probe_wait * 2,
				    MAX(lag->recovery_probe_max, lag->recovery_probe));
	monotime(&m->held_at);

	/*
	 * RFC 7130, Section 3: held down, it sends nothing. Deleted from the
	 * event loop: this may run from one of the sessions' own callbacks.
	 */
	event_cancel(&m->t_dist_stop);
	event_add_timer_msec(master, lag_dist_stop_cb, m, 0, &m->t_dist_stop);
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
		if (m->s[af].admin_hold_expired)
			return "peer AdminDown, hold expired";
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

static void lag_noses_cb(struct event *t)
{
	lag_member_evaluate(EVENT_ARG(t));
}

static void lag_nbr_wait_cb(struct event *t)
{
	struct bfd_lag_member *m = EVENT_ARG(t);

	m->nbr_wait_done = true;
	lag_member_evaluate(m);
}

/*
 * A loss in one direction is seen by both ends: the end that stops
 * receiving (detection time expired) goes Down first, and tells the other
 * (neighbor signaled session down). Only the first should hold its member
 * down: the other waits a detection time, by which it has lost carrier.
 * Returns true while waiting.
 */
static bool lag_member_nbr_wait(struct bfd_lag_member *m, const bool *deciding)
{
	uint64_t wait = 0;

	if (m->nbr_wait_done)
		return false;

	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		const struct bfd_session *bs = m->s[af].bs;

		if (!deciding[af] || bs->ses_state == PTM_BFD_UP)
			continue;
		if (bs->local_diag != BD_NEIGHBOR_DOWN)
			return false;
		wait = MAX(wait, bs->detect_TO / 1000);
	}
	if (!wait)
		return false;

	if (!event_is_scheduled(m->t_nbr_wait)) {
		LAG_DEBUG("lag %s member %s: peer signalled down, waiting %" PRIu64
			  " ms for it to act first",
			  m->lag->name, m->name, wait);
		event_add_timer_msec(master, lag_nbr_wait_cb, m, wait, &m->t_nbr_wait);
	}
	return true;
}

/* A member held down: release it when micro-BFD no longer decides. */
static void lag_member_evaluate_held(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;
	const char *fail_open = NULL;
	int64_t since;

	if (lag->admin_down) {
		fail_open = "shutdown";
	} else {
		/*
		 * No session can run (configuration, bond address): release it,
		 * once that lasts (BFD_LAG_HELD_NOSES_DELAY).
		 */
		fail_open = lag_no_session_reason(lag);
		if (!fail_open) {
			timerclear(&m->noses_since);
			event_cancel(&m->t_noses);
		} else {
			if (!timerisset(&m->noses_since))
				monotime(&m->noses_since);
			since = monotime_since(&m->noses_since, NULL) / 1000;
			if (since < BFD_LAG_HELD_NOSES_DELAY) {
				if (!event_is_scheduled(m->t_noses))
					event_add_timer_msec(master, lag_noses_cb, m,
							     BFD_LAG_HELD_NOSES_DELAY - since,
							     &m->t_noses);
				fail_open = NULL;
			}
		}
	}

	if (fail_open) {
		m->reason = fail_open;
		timerclear(&m->noses_since);
		lag_member_request(m, true, fail_open);
		return;
	}

	if (!m->reason)
		m->reason = "session down";
	lag_member_probe_arm(m);
}

/*
 * Decide whether the member should carry traffic, and ask zebra for the
 * change. Called on every event that could change the answer.
 */
static void lag_member_evaluate(struct bfd_lag_member *m)
{
	struct bfd_lag *lag = m->lag;
	bool deciding[BFD_LAG_AF_MAX] = {};
	bool any = false, all_up = true, shut = false, peer_admin = false;

	if (!lag->registered || lag->ifindex == IFINDEX_INTERNAL)
		return;

	/* Wait for the kernel, and for zebra to answer the last request. */
	if (CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PENDING) || m->req_outstanding)
		return;

	if (bfd_lag_member_detached(m)) {
		lag_member_evaluate_held(m);
		return;
	}

	/*
	 * Settling, it distributed but no longer does while its link stays up
	 * (LACP still converging): the sessions get BFD_LAG_SETTLE_UP afresh
	 * once it does again, within BFD_LAG_SETTLE_MAX of the release. Losing
	 * the link instead (the peer holds its end down) keeps the window.
	 */
	if (m->settling && m->settle_dist && !lag_member_eligible(m) &&
	    CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_OPER_UP)) {
		int64_t since = monotime_since(&m->last_action, NULL) / 1000;

		m->settle_dist = false;
		event_cancel(&m->t_settle);
		event_add_timer_msec(master, lag_settle_cb, m, MAX(BFD_LAG_SETTLE_MAX - since, 0),
				     &m->t_settle);
	}

	/*
	 * The sessions that decide: running, not shut down, and whose peer
	 * doesn't signal AdminDown. All of them must be Up (A1).
	 */
	for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++) {
		struct bfd_lag_msess *ms = &m->s[af];

		if (!ms->bs)
			continue;
		if (ms->bs->ses_state == PTM_BFD_ADM_DOWN) {
			shut = true;
			continue;
		}
		/*
		 * A session that was never Up has no state change to report the
		 * peer's AdminDown (Down stays Down): after a recovery probe all
		 * sessions are new, and a peer that is shut down must not hold
		 * the member down (RFC 5882). Only once a packet came: the
		 * remote state starts as AdminDown (0).
		 */
		if (!ms->peer_admin_down && ms->bs->discrs.remote_discr &&
		    ms->bs->remote_ses_state == PTM_BFD_ADM_DOWN &&
		    ms->bs->ses_state != PTM_BFD_UP) {
			ms->peer_admin_down = true;
			monotime(&ms->admin_down_at);
			lag_admin_hold_arm(ms);
		}
		if (ms->peer_admin_down && ms->bs->ses_state != PTM_BFD_UP &&
		    !ms->admin_hold_expired) {
			peer_admin = true;
			continue;
		}
		deciding[af] = true;
		any = true;
		if (ms->bs->ses_state != PTM_BFD_UP)
			all_up = false;
	}

	/* Nothing decides: not a failure, the member is left alone. */
	if (!any) {
		event_cancel(&m->t_stable);
		if (!m->sess_active)
			m->reason = m->settling ? "attach-settle (waiting for LACP)"
						: "not distributing (no sessions)";
		else if (shut)
			m->reason = "shutdown";
		else if (peer_admin)
			m->reason = "peer signalled AdminDown";
		else
			m->reason = lag_no_session_reason(lag);
		if (!m->reason)
			m->reason = "no session";
		return;
	}

	if (all_up) {
		m->ever_up = true;
		m->setup_expired = false;
		m->nbr_wait_done = false;
		event_cancel(&m->t_nbr_wait);
		event_cancel(&m->t_setup);
		if (m->settling) {
			m->settling = false;
			event_cancel(&m->t_settle);
			LAG_DEBUG("lag %s member %s: settled", lag->name, m->name);
		}
		if (m->probing)
			zlog_info("micro-BFD: lag %s member %s: recovery probe succeeded",
				  lag->name, m->name);
		m->probing = false;
		if (m->probe_wait && !event_is_scheduled(m->t_stable))
			event_add_timer_msec(master, lag_stable_cb, m, BFD_LAG_PROBE_STABLE,
					     &m->t_stable);
		m->reason = NULL;
		return;
	}

	/* A deciding session is not Up. */
	event_cancel(&m->t_stable);

	/*
	 * Settling, distributing (or standby) again: the sessions get
	 * BFD_LAG_SETTLE_UP from now (the peer only starts its own now).
	 */
	if (m->settling && !m->settle_dist && lag_member_eligible(m)) {
		m->settle_dist = true;
		event_cancel(&m->t_settle);
		event_add_timer_msec(master, lag_settle_cb, m,
				     MAX(BFD_LAG_SETTLE_UP,
					 lag->mode == BFD_LAG_MODE_STRICT ? lag->enable_grace : 0),
				     &m->t_settle);
	}
	if (m->settling) {
		m->reason = "attach-settle";
		return;
	}
	if (lag->mode == BFD_LAG_MODE_STRICT && m->in_grace && !m->probing) {
		m->reason = "enable-grace";
		return;
	}
	/*
	 * LACP taking a member out is not a micro-BFD failure; only a member
	 * that carries traffic (or is standby) is held down (its sessions go
	 * when the delay is over).
	 */
	if (!lag_member_eligible(m)) {
		m->reason = "not distributing";
		return;
	}
	/*
	 * distributing-only: a session that never came Up only holds the
	 * member down when max-setup-time is over; a recovery probe's
	 * sessions get the settle time only.
	 */
	if (lag->mode == BFD_LAG_MODE_DIST_ONLY && !m->ever_up && !m->setup_expired && !m->probing) {
		m->reason = lag->max_setup ? "waiting for session"
					   : "waiting for session (max-setup-time off)";
		return;
	}
	if (CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PROTODOWN)) {
		m->reason = "protodown";
		return;
	}
	if (!m->probing && lag_member_nbr_wait(m, deciding)) {
		m->reason = "peer signalled down, waiting for it";
		return;
	}

	m->reason = lag_down_reason(m, deciding);
	/* admin-down-hold over says more than the probe failing. */
	if (m->probing && strcmp(m->reason, "peer AdminDown, hold expired"))
		m->reason = "recovery probe failed";
	else if (!m->probing && lag->mode == BFD_LAG_MODE_DIST_ONLY && !m->ever_up)
		m->reason = "max-setup-time expired";
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
	case PTM_BFD_ADM_DOWN:
		/* Local shutdown has the session AdminDown itself. */
		if (bs->ses_state != PTM_BFD_ADM_DOWN && !ms->peer_admin_down) {
			ms->peer_admin_down = true;
			monotime(&ms->admin_down_at);
			lag_admin_hold_arm(ms);
		}
		break;
	default:
		ms->peer_admin_down = false;
		lag_admin_hold_stop(ms);
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

	lag_fail_mode_check(lag);
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

	lag_member_sessions_update(m);
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
	lag->max_setup = BFD_LAG_MAX_SETUP_DEF;
	lag->recovery_probe = BFD_LAG_RECOVERY_PROBE_DEF;
	lag->recovery_probe_max = BFD_LAG_RECOVERY_PROBE_MAX_DEF;
	lag->fail_mode = BFD_LAG_FAIL_OPEN;
	lag->admin_down_hold = BFD_LAG_ADMIN_DOWN_HOLD_DEF;
	lag->ifindex = IFINDEX_INTERNAL;
	lag->vrf_id = VRF_DEFAULT;
	bfd_lag_members_init(&lag->members);
	bfd_lags_add_tail(&bfd_lags, lag);

	/*
	 * Registered with zebra in bfd_lag_apply(), once the whole
	 * configuration is in: zebra must not see a failure-mode the
	 * configuration doesn't have, nor members before the addresses.
	 */
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
		lag_member_admtx_update(m);
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

/*
 * A mode change restarts the LAG (fail-open): members micro-BFD holds down
 * are released, sessions stop (AdminDown) and start again under the new
 * mode's rules, when the configuration is applied (bfd_lag_apply()).
 */
void bfd_lag_set_mode(struct bfd_lag *lag, enum bfd_lag_mode mode)
{
	struct bfd_lag_member *m;

	if (lag->mode == mode)
		return;
	lag->mode = mode;
	zlog_info("micro-BFD: lag %s: mode %s, restarting its sessions", lag->name,
		  bfd_lag_mode2str(mode));

	frr_each (bfd_lag_members, &lag->members, m) {
		lag_member_sessions_delete(m);
		lag_member_sessions_reset(m);
		m->in_grace = false;
		event_cancel(&m->t_grace);
		m->probe_wait = 0;
		if (lag->registered && bfd_lag_member_detached(m) && !m->req_outstanding)
			lag_member_request(m, true, "mode changed");
	}
}

/* Applies from the next time a member's sessions start. */
void bfd_lag_set_max_setup(struct bfd_lag *lag, uint32_t ms)
{
	lag->max_setup = ms;
}

void bfd_lag_set_recovery_probe(struct bfd_lag *lag, uint32_t ms)
{
	struct bfd_lag_member *m;

	lag->recovery_probe = ms;
	frr_each (bfd_lag_members, &lag->members, m) {
		m->probe_wait = 0;
		event_cancel(&m->t_probe);
		lag_member_probe_arm(m);
	}
}

void bfd_lag_set_recovery_probe_max(struct bfd_lag *lag, uint32_t ms)
{
	struct bfd_lag_member *m;

	lag->recovery_probe_max = ms;
	frr_each (bfd_lag_members, &lag->members, m) {
		if (m->probe_wait > MAX(ms, lag->recovery_probe))
			m->probe_wait = MAX(ms, lag->recovery_probe);
		event_cancel(&m->t_probe);
		lag_member_probe_arm(m);
	}
}

void bfd_lag_set_enable_grace(struct bfd_lag *lag, uint32_t ms)
{
	lag->enable_grace = ms;
}

void bfd_lag_set_fail_mode(struct bfd_lag *lag, enum bfd_lag_fail_mode mode)
{
	if (lag->fail_mode == mode)
		return;
	lag->fail_mode = mode;

	/* Zebra takes the new flags from a second registration, in place. */
	if (lag->registered && bfdd_zclient_lag_register(lag->vrf_id, lag->registered_ifindex,
							 true, mode == BFD_LAG_FAIL_OPEN) != 0)
		zlog_warn("micro-BFD: lag %s: can't tell zebra failure-mode %s", lag->name,
			  bfd_lag_fail_mode2str(mode));
	LAG_DEBUG("lag %s: failure-mode %s", lag->name, bfd_lag_fail_mode2str(mode));
	lag_fail_mode_check(lag);
}

void bfd_lag_set_admin_down_hold(struct bfd_lag *lag, uint32_t ms)
{
	struct bfd_lag_member *m;

	if (lag->admin_down_hold == ms)
		return;
	lag->admin_down_hold = ms;

	/* Holds running (or over) follow the new value. */
	frr_each (bfd_lag_members, &lag->members, m) {
		for (enum bfd_lag_af af = 0; af < BFD_LAG_AF_MAX; af++)
			if (m->s[af].bs && m->s[af].peer_admin_down)
				lag_admin_hold_arm(&m->s[af]);
		lag_member_evaluate(m);
	}
}

/* After a configuration change: start, stop or re-evaluate sessions. */
void bfd_lag_apply(struct bfd_lag *lag)
{
	/* Nothing left to run: as if the configuration were removed. */
	if (!lag_configured(lag) && lag->registered) {
		lag_members_free(lag);
		lag_unregister(lag);
	}
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
	json_object_int_add(js, "adminDownHoldRemaining", lag_admin_hold_left(ms));
	json_object_boolean_add(js, "adminDownHoldExpired", ms->admin_hold_expired);
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
		json_object_boolean_add(jm, "heldDown", detached);
		json_object_boolean_add(jm, "distributing", distributing);
		json_object_boolean_add(jm, "standby", bfd_lag_member_standby(m));
		json_object_boolean_add(jm, "kernelAttached",
					CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_KERNEL_ATTACHED));
		json_object_boolean_add(jm, "pending",
					CHECK_FLAG(m->zflags, ZAPI_LAG_MBR_F_PENDING));
		json_object_string_add(jm, "zebraFlags",
				       zapi_lag_mbr_flags2str(m->zflags, buf, sizeof(buf)));
		json_object_string_add(jm, "reason", m->reason ? m->reason : "");
		json_object_boolean_add(jm, "enableGrace", m->in_grace);
		json_object_boolean_add(jm, "settling", m->settling);
		json_object_boolean_add(jm, "sessionActive", m->sess_active);
		json_object_boolean_add(jm, "maxSetupExpired", m->setup_expired);
		json_object_boolean_add(jm, "probing", m->probing);
		json_object_int_add(jm, "probeCount", m->stats.probe_count);
		json_object_int_add(jm, "nextProbeIn", lag_member_probe_left(m));
		json_object_int_add(jm, "probeWait", detached ? lag_probe_wait(m) : m->probe_wait);
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

	vty_out(vty, "    member %s: %s%s%s%s\n", m->name, detached ? "held down" : "in",
		distributing ? ", distributing" : "", bfd_lag_member_standby(m) ? ", standby" : "",
		!m->sess_active ? ", no sessions" : "");
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
		if (ms->t_admin_hold)
			vty_out(vty, "        admin-down-hold: %u ms left\n",
				lag_admin_hold_left(ms));
		else if (ms->admin_hold_expired)
			vty_out(vty, "        admin-down-hold: over\n");
		vty_out(vty, "        diagnostics: local %s, remote %s\n",
			diag2str(bs->local_diag), diag2str(bs->remote_diag));
	}
	if (!lag_member_has_session(m))
		vty_out(vty, "      no session\n");
	if (m->reason)
		vty_out(vty, "      reason: %s\n", m->reason);
	vty_out(vty, "      zebra: %s\n", zapi_lag_mbr_flags2str(m->zflags, buf, sizeof(buf)));
	vty_out(vty,
		"      held down %" PRIu64 " times, released %" PRIu64
		" times, recovery probes %" PRIu64 "%s\n",
		m->stats.detach_count, m->stats.attach_count, m->stats.probe_count,
		m->probing ? " (probing now)" : "");
	if (m->t_probe)
		vty_out(vty, "      recovery probe in %u ms (wait %u ms)\n",
			lag_member_probe_left(m), lag_probe_wait(m));
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
		json_object_int_add(jl, "maxSetupTime", lag->max_setup);
		json_object_int_add(jl, "recoveryProbeTime", lag->recovery_probe);
		json_object_int_add(jl, "recoveryProbeMax", lag->recovery_probe_max);
		json_object_string_add(jl, "failureMode", bfd_lag_fail_mode2str(lag->fail_mode));
		json_object_int_add(jl, "adminDownHold", lag->admin_down_hold);
		json_object_string_add(jl, "noSessionReason", no_session ? no_session : "");
		if (detect && detect < BFD_LAG_MIN_DETECT_WARN)
			json_object_string_addf(jl, "warning",
						"detection time %u ms is below %u ms", detect,
						BFD_LAG_MIN_DETECT_WARN);
		if (lag_fail_mode_risky(lag))
			json_object_string_add(jl, "failureModeWarning",
					       "failure-mode open on a balance-xor bond");
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
	vty_out(vty, "  profile %s, enable-grace %u ms%s, max-setup-time %u ms%s\n",
		lag->profile_name ? lag->profile_name : "-", lag->enable_grace,
		lag->mode == BFD_LAG_MODE_STRICT ? "" : " (not used in this mode)", lag->max_setup,
		lag->mode == BFD_LAG_MODE_DIST_ONLY ? "" : " (not used in this mode)");
	if (lag->mode == BFD_LAG_MODE_DIST_ONLY)
		vty_out(vty,
			"  note: distributing-only lets a member carry traffic before its sessions are Up (not RFC 7130 strict)\n");
	if (lag->recovery_probe)
		vty_out(vty, "  recovery-probe-time %u ms, recovery-probe-max %u ms\n",
			lag->recovery_probe, MAX(lag->recovery_probe_max, lag->recovery_probe));
	else
		vty_out(vty,
			"  recovery-probe-time 0 (off): a member held down stays down until the configuration changes\n");
	vty_out(vty, "  failure-mode %s, admin-down-hold %u ms%s\n",
		bfd_lag_fail_mode2str(lag->fail_mode), lag->admin_down_hold,
		lag->admin_down_hold ? "" : " (as long as AdminDown lasts)");
	if (lag_fail_mode_risky(lag))
		vty_out(vty,
			"  warning: failure-mode open on a balance-xor bond; if bfdd stops, members the peer keeps out are put back\n");
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
