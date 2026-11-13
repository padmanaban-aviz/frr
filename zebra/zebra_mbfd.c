// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra RFC 7130 micro-BFD support: bond (LAG) member tracking and control.
 *
 * bfdd runs one BFD session per bond member (RFC 7130). When a member's
 * session fails, the member must stop carrying the bond's traffic. Zebra
 * owns the kernel, so bfdd asks zebra:
 *
 * - ZEBRA_LAG_MBFD_REGISTER: track this bond. Zebra answers with
 *   ZEBRA_LAG_MBFD_BOND_STATUS and, when the bond is usable, a
 *   ZEBRA_LAG_MBFD_MEMBER_UPDATE per member, then one per member change.
 * - ZEBRA_LAG_MBFD_DIST_SET: hold a member down ("detach") or release it
 *   ("attach").
 *
 * Holding a member down sets it administratively down: it stays in the
 * bond, the bond stops using it, and the peer loses carrier at once.
 * Releasing it sets it up again, but only if it was up when micro-BFD set
 * it down (a member the operator set down stays down); LACP then
 * negotiates on it again. zebra_if->mbfd.home_bond keeps the bond of a
 * member held down, and WAS_UP whether zebra must set it up again.
 *
 * Fail-open: when the client unregisters or goes away (including zebra's own
 * shutdown, which closes clients first), members held down are released,
 * unless the bond was registered without ZAPI_LAG_REG_F_FAIL_OPEN. They are
 * recorded in a state file so a restarted zebra can release (fail-open) or
 * keep holding (fail-closed) them.
 *
 * If something else (an operator, NetworkManager, ...) sets up a member
 * micro-BFD holds down, zebra sets it down again with back-off.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#include <zebra.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "lib/if.h"
#include "lib/libfrr.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include "lib/vty.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/ioctl.h"
#include "zebra/rt.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_mbfd.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_MBFD_REG, "micro-BFD bond registration");
DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_MBFD_SAVED, "micro-BFD saved member state");

/* A bond registered by a client. */
PREDECL_DLIST(mbfd_regs);
struct mbfd_reg {
	struct mbfd_regs_item item;

	struct zebra_ns *zns;
	vrf_id_t vrf_id; /* bond's VRF, for messages to the client */
	ifindex_t bond_ifindex;

	struct zserv *client;
	uint8_t flags; /* ZAPI_LAG_REG_F_* */

	/* last status sent to the client */
	bool status_sent;
	uint8_t status;
};
DECLARE_DLIST(mbfd_regs, struct mbfd_reg, item);

static struct mbfd_regs_head mbfd_regs;

/*
 * State file lines loaded at startup and not acted on yet. They are kept in
 * every state file write until handled, so a detach done in the first
 * seconds after a restart can't wipe them out, and is saved itself.
 */
PREDECL_DLIST(mbfd_saved);
struct mbfd_saved {
	struct mbfd_saved_item item;
	char mname[IFNAMSIZ + 1];
	char bname[IFNAMSIZ + 1];
	int failopen;
	int was_up;
};
DECLARE_DLIST(mbfd_saved, struct mbfd_saved, item);

static struct mbfd_saved_head mbfd_saved;
static struct event *t_state_read;
static unsigned int state_read_tries;

#define MBFD_STATE_FILE		"zebra_mbfd.state"
#define MBFD_STATE_READ_DELAY	5 /* seconds after startup */
#define MBFD_STATE_READ_RETRIES 6

/* LACP actor state poll of registered bonds' members (ms), see below. */
#define MBFD_AD_POLL_MS 1000
static struct event *t_ad_poll;
static void mbfd_ad_poll_schedule(void);

/*
 * Micro-BFD moves members in and out of their bond, but never changes their
 * administrative state: a member the operator set down stays down, out of
 * the bond or back in it.
 *
 * Ask the kernel rather than trust ifp->flags: when a member is set down,
 * its sessions can fail, and bfdd ask for it to be taken out, before zebra
 * has read the netlink event; setting it up after the release would then
 * undo the operator's "down".
 */
static bool mbfd_admin_up(const struct interface *ifp)
{
	struct ifreq ifr = {};

	strlcpy(ifr.ifr_name, ifp->name, sizeof(ifr.ifr_name));
	if (vrf_if_ioctl(SIOCGIFFLAGS, (caddr_t)&ifr, ifp->vrf->vrf_id) < 0)
		return CHECK_FLAG(ifp->flags, IFF_UP);

	return CHECK_FLAG(ifr.ifr_flags, IFF_UP);
}

static uint32_t mbfd_enslave_flags(const struct interface *ifp)
{
	return DPLANE_INTF_MASTER_F_DOWN_FIRST |
	       (mbfd_admin_up(ifp) ? 0 : DPLANE_INTF_MASTER_F_DOWN_AFTER);
}

static void mbfd_state_write(void);
static void mbfd_guard_cb(struct event *t);

/*
 * Helpers
 */
static struct zebra_ns *mbfd_if_zns(const struct interface *ifp)
{
	struct zebra_vrf *zvrf = ifp->vrf ? ifp->vrf->info : NULL;

	return zvrf ? zvrf->zns : NULL;
}

static struct mbfd_reg *mbfd_reg_find(const struct zebra_ns *zns, ifindex_t bond_ifindex)
{
	struct mbfd_reg *reg;

	frr_each (mbfd_regs, &mbfd_regs, reg)
		if (reg->zns == zns && reg->bond_ifindex == bond_ifindex)
			return reg;

	return NULL;
}

static struct interface *mbfd_reg_bond(const struct mbfd_reg *reg)
{
	struct interface *ifp;

	if (!reg->zns)
		return NULL;

	ifp = if_lookup_by_index_per_ns(reg->zns, reg->bond_ifindex);
	return (ifp && IS_ZEBRA_IF_BOND(ifp)) ? ifp : NULL;
}

/* The bond the kernel has this interface enslaved to, or 0. */
static ifindex_t mbfd_kernel_bond(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;

	if (!zif || !IS_ZEBRA_IF_BOND_SLAVE(ifp))
		return IFINDEX_INTERNAL;

	return zif->bondslave_info.bond_ifindex;
}

/* The bond this interface is a (kernel or logical) member of, or 0. */
static ifindex_t mbfd_member_bond(const struct interface *ifp)
{
	const struct zebra_if *zif = ifp->info;
	ifindex_t kbond = mbfd_kernel_bond(ifp);

	if (kbond != IFINDEX_INTERNAL)
		return kbond;
	if (zif && CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED))
		return zif->mbfd.home_bond;

	return IFINDEX_INTERNAL;
}

typedef void (*mbfd_if_walk_cb)(struct interface *ifp, void *arg);

/* Call `cb` for every interface in namespace `zns`. */
static void mbfd_if_walk(const struct zebra_ns *zns, mbfd_if_walk_cb cb, void *arg)
{
	struct interface *ifp, *tmp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		struct zebra_vrf *zvrf = vrf->info;

		if (!zvrf || (zns && zvrf->zns != zns))
			continue;
		RB_FOREACH_SAFE (ifp, if_name_head, &vrf->ifaces_by_name, tmp)
			if (ifp->info)
				cb(ifp, arg);
	}
}

struct mbfd_count_arg {
	ifindex_t bond;
	unsigned int count;
};

static void mbfd_count_cb(struct interface *ifp, void *arg)
{
	struct mbfd_count_arg *ca = arg;

	if (mbfd_member_bond(ifp) == ca->bond)
		ca->count++;
}

static uint8_t mbfd_bond_status(const struct mbfd_reg *reg, uint8_t *mode, uint8_t *count)
{
	struct interface *bond = mbfd_reg_bond(reg);
	struct mbfd_count_arg ca = { .bond = reg->bond_ifindex };
	struct zebra_if *zif;

	*mode = ZAPI_LAG_BOND_MODE_UNKNOWN;
	*count = 0;

	if (!bond)
		return ZAPI_LAG_BOND_NOT_FOUND;

	zif = bond->info;
	if (zif->bond_info.mode_valid)
		*mode = zif->bond_info.mode;

	mbfd_if_walk(reg->zns, mbfd_count_cb, &ca);
	*count = MIN(ca.count, UINT8_MAX);

	if (zif->es_info.es)
		return ZAPI_LAG_BOND_EVPN_ES;
	if (!zif->bond_info.mode_valid || (zif->bond_info.mode != ZEBRA_BOND_MODE_8023AD &&
					   zif->bond_info.mode != ZEBRA_BOND_MODE_XOR))
		return ZAPI_LAG_BOND_UNSUPPORTED_MODE;

	return ZAPI_LAG_BOND_OK;
}

/*
 * Standby (RFC 7130, Section 3): aggregated with a partner (LACP running,
 * partner information current) in an aggregator that isn't the bond's
 * active one, while the bond is up on that active one: ready to take over.
 * Linux keeps such a port out of sync, so Sync can't tell; a port whose
 * partner timed out (expired, defaulted) sits in an aggregator of its own
 * and isn't standby. While LACP negotiates, ports pass through aggregators
 * of their own too: the poll reports standby only once it lasted
 * MBFD_STANDBY_STABLE_MS.
 */
#define MBFD_STANDBY_STABLE_MS 3000

static bool mbfd_standby_now(const struct interface *ifp, ifindex_t bond_ifindex)
{
	const struct zebra_if *zif = ifp->info;
	struct interface *bond;
	const struct zebra_if *bzif;

	if (mbfd_kernel_bond(ifp) != bond_ifindex || !if_is_operative(ifp))
		return false;
	bond = if_lookup_by_index_per_ns(mbfd_if_zns(ifp), bond_ifindex);
	bzif = bond ? bond->info : NULL;
	if (!bzif || !bzif->bond_info.mode_valid ||
	    bzif->bond_info.mode != ZEBRA_BOND_MODE_8023AD || !if_is_operative(bond))
		return false;
	if (!zif->mbfd.agg_valid || !zif->mbfd.agg_id ||
	    zif->mbfd.agg_id == zif->mbfd.active_agg_id ||
	    !zif->bondslave_info.ad_actor_state_valid)
		return false;
	if (CHECK_FLAG(zif->bondslave_info.ad_actor_oper_state, ZEBRA_LACP_STATE_DISTRIBUTING))
		return false;
	return CHECK_FLAG(zif->bondslave_info.ad_actor_oper_state, ZEBRA_LACP_STATE_AGGREGATION) &&
	       !CHECK_FLAG(zif->bondslave_info.ad_actor_oper_state,
			   ZEBRA_LACP_STATE_DEFAULTED | ZEBRA_LACP_STATE_EXPIRED);
}

/* Member flags as reported to the client (ZAPI_LAG_MBR_F_*). */
static uint16_t mbfd_member_flags(const struct interface *ifp, ifindex_t bond_ifindex,
				  uint8_t *ad_state)
{
	const struct zebra_if *zif = ifp->info;
	const struct zebra_if *bzif;
	struct interface *bond;
	bool attached, oper_up, distributing = false;
	uint16_t flags = 0;

	*ad_state = 0;

	attached = mbfd_kernel_bond(ifp) == bond_ifindex;
	oper_up = if_is_operative(ifp);

	if (attached)
		SET_FLAG(flags, ZAPI_LAG_MBR_F_KERNEL_ATTACHED);
	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED))
		SET_FLAG(flags, ZAPI_LAG_MBR_F_MBFD_DETACHED);
	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH | ZEBRA_MBFD_F_PEND_ATTACH))
		SET_FLAG(flags, ZAPI_LAG_MBR_F_PENDING);
	if (oper_up)
		SET_FLAG(flags, ZAPI_LAG_MBR_F_OPER_UP);
	if (if_is_up(ifp))
		SET_FLAG(flags, ZAPI_LAG_MBR_F_ADMIN_UP);
	if (ZEBRA_IF_IS_PROTODOWN(zif))
		SET_FLAG(flags, ZAPI_LAG_MBR_F_PROTODOWN);
	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED))
		SET_FLAG(flags, ZAPI_LAG_MBR_F_EXT_REENSLAVED);
	if (attached && zif->bondslave_info.ad_actor_state_valid) {
		SET_FLAG(flags, ZAPI_LAG_MBR_F_AD_STATE_VALID);
		*ad_state = zif->bondslave_info.ad_actor_oper_state;
	}

	/*
	 * Distributing: the member carries the bond's traffic.
	 *
	 * Require carrier as well: on carrier loss the kernel changes the
	 * member's LACP state but only reports it with a later event, while
	 * the carrier change itself is reported at once.
	 */
	bond = mbfd_kernel_bond(ifp) != IFINDEX_INTERNAL
		       ? if_lookup_by_index_per_ns(mbfd_if_zns(ifp), bond_ifindex)
		       : NULL;
	bzif = bond ? bond->info : NULL;
	if (attached && oper_up && bzif && bzif->bond_info.mode_valid) {
		if (bzif->bond_info.mode == ZEBRA_BOND_MODE_8023AD)
			distributing = zif->bondslave_info.ad_actor_state_valid &&
				       CHECK_FLAG(zif->bondslave_info.ad_actor_oper_state,
						  ZEBRA_LACP_STATE_DISTRIBUTING);
		else
			distributing = true;
	}
	if (distributing)
		SET_FLAG(flags, ZAPI_LAG_MBR_F_DISTRIBUTING);

	/* Standby: as the poll last saw it, and still so now. */
	if (!distributing && zif->mbfd.standby && mbfd_standby_now(ifp, bond_ifindex))
		SET_FLAG(flags, ZAPI_LAG_MBR_F_STANDBY);

	return flags;
}

/*
 * Messages to the client
 */
static void mbfd_send_status(struct mbfd_reg *reg, bool force)
{
	struct zapi_lag_bond_status st = { .bond_ifindex = reg->bond_ifindex };
	struct stream *s;

	st.status = mbfd_bond_status(reg, &st.bond_mode, &st.member_count);
	if (!force && reg->status_sent && reg->status == st.status)
		return;

	reg->status = st.status;
	reg->status_sent = true;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("micro-BFD: bond ifindex %u status %s (mode %u, %u members) to %s",
			   reg->bond_ifindex, zapi_lag_bond_status2str(st.status), st.bond_mode,
			   st.member_count, zebra_route_string(reg->client->proto));

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zapi_lag_bond_status_encode(s, reg->vrf_id, &st);
	zserv_send_message(reg->client, s);
}

static void mbfd_send_member(struct mbfd_reg *reg, struct interface *ifp, uint8_t op,
			     uint16_t flags, uint8_t ad_state)
{
	struct zapi_lag_member mbr = {
		.op = op,
		.bond_ifindex = reg->bond_ifindex,
		.mbr_ifindex = ifp->ifindex,
		.flags = flags,
		.ad_actor_state = ad_state,
	};
	struct stream *s;

	strlcpy(mbr.mbr_name, ifp->name, sizeof(mbr.mbr_name));
	if (ifp->hw_addr_len == ETH_ALEN)
		memcpy(mbr.mac, ifp->hw_addr, ETH_ALEN);

	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf[128];

		zlog_debug("micro-BFD: member %s %s bond ifindex %u flags %s ad 0x%02x to %s",
			   ifp->name, zapi_lag_mbr_op2str(op), reg->bond_ifindex,
			   zapi_lag_mbr_flags2str(flags, buf, sizeof(buf)), ad_state,
			   zebra_route_string(reg->client->proto));
	}

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zapi_lag_member_encode(s, reg->vrf_id, &mbr);
	zserv_send_message(reg->client, s);
}

/* A registration the client should hear about. */
static struct mbfd_reg *mbfd_reg_active(const struct zebra_ns *zns, ifindex_t bond_ifindex)
{
	struct mbfd_reg *reg = mbfd_reg_find(zns, bond_ifindex);

	if (!reg || !reg->client || !reg->status_sent || reg->status != ZAPI_LAG_BOND_OK)
		return NULL;

	return reg;
}

/*
 * Report a member's current state if it changed: ADD when it becomes a
 * member of a registered bond, UPDATE on change, DEL when it leaves.
 */
static void mbfd_notify_member(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_ns *zns = mbfd_if_zns(ifp);
	ifindex_t bond = mbfd_member_bond(ifp);
	struct mbfd_reg *reg;
	uint16_t flags;
	uint8_t ad;

	if (!zif)
		return;

	if (zif->mbfd.notified_bond != IFINDEX_INTERNAL && zif->mbfd.notified_bond != bond) {
		reg = mbfd_reg_active(zns, zif->mbfd.notified_bond);
		if (reg)
			mbfd_send_member(reg, ifp, ZAPI_LAG_MBR_DEL, zif->mbfd.last_flags,
					 zif->mbfd.last_ad_state);
		zif->mbfd.notified_bond = IFINDEX_INTERNAL;
	}

	if (bond == IFINDEX_INTERNAL)
		return;

	reg = mbfd_reg_active(zns, bond);
	if (!reg)
		return;

	flags = mbfd_member_flags(ifp, bond, &ad);

	if (zif->mbfd.notified_bond == bond && zif->mbfd.last_flags == flags &&
	    zif->mbfd.last_ad_state == ad &&
	    (ifp->hw_addr_len != ETH_ALEN ||
	     memcmp(zif->mbfd.last_mac, ifp->hw_addr, ETH_ALEN) == 0))
		return;

	mbfd_send_member(reg, ifp,
			 zif->mbfd.notified_bond == bond ? ZAPI_LAG_MBR_UPDATE : ZAPI_LAG_MBR_ADD,
			 flags, ad);

	zif->mbfd.notified_bond = bond;
	zif->mbfd.last_flags = flags;
	zif->mbfd.last_ad_state = ad;
	if (ifp->hw_addr_len == ETH_ALEN)
		memcpy(zif->mbfd.last_mac, ifp->hw_addr, ETH_ALEN);
}

/* Forget what was reported for the members of `bond`, so they are re-sent. */
static void mbfd_forget_cb(struct interface *ifp, void *arg)
{
	struct zebra_if *zif = ifp->info;
	ifindex_t bond = *(ifindex_t *)arg;

	if (zif->mbfd.notified_bond == bond)
		zif->mbfd.notified_bond = IFINDEX_INTERNAL;
}

static void mbfd_notify_cb(struct interface *ifp, void *arg)
{
	ifindex_t bond = *(ifindex_t *)arg;

	if (mbfd_member_bond(ifp) == bond)
		mbfd_notify_member(ifp);
}

/* (Re)send the bond status and, when usable, every member as ADD. */
static void mbfd_reg_resync(struct mbfd_reg *reg)
{
	mbfd_if_walk(reg->zns, mbfd_forget_cb, &reg->bond_ifindex);
	mbfd_send_status(reg, true);
	if (reg->status == ZAPI_LAG_BOND_OK)
		mbfd_if_walk(reg->zns, mbfd_notify_cb, &reg->bond_ifindex);
}

/*
 * Member state machine
 */
static void mbfd_member_clear(struct zebra_if *zif)
{
	zif->mbfd.home_bond = IFINDEX_INTERNAL;
	zif->mbfd.flags = 0;
	zif->mbfd.guard_backoff = 0;
	event_cancel(&zif->mbfd.t_guard);
}

/* Release a member micro-BFD holds down (fail-open). */
static void mbfd_member_reattach(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_ns *zns = mbfd_if_zns(ifp);
	ifindex_t home = zif->mbfd.home_bond;
	struct interface *bond = zns ? if_lookup_by_index_per_ns(zns, home) : NULL;
	bool was_up = CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_WAS_UP);

	mbfd_member_clear(zif);

	if (!bond || !IS_ZEBRA_IF_BOND(bond))
		return;

	/* Out of its bond (state file of an older zebra): put it back. */
	if (mbfd_kernel_bond(ifp) != home) {
		zlog_info("micro-BFD: re-attaching %s to %s (fail-open)", ifp->name, bond->name);
		if (dplane_intf_set_master(ifp, bond, mbfd_enslave_flags(ifp)) ==
			    ZEBRA_DPLANE_REQUEST_FAILURE &&
		    zns)
			kernel_intf_set_master_sync(zns, ifp->ifindex, true, bond->ifindex,
						    DPLANE_INTF_ADMIN_DOWN, NULL);
		return;
	}

	if (!was_up || mbfd_admin_up(ifp))
		return;

	zlog_info("micro-BFD: releasing %s (fail-open), setting it up", ifp->name);
	if (dplane_intf_set_admin(ifp, true) == ZEBRA_DPLANE_REQUEST_FAILURE && zns)
		/* Dataplane gone (late in shutdown): do it synchronously. */
		kernel_intf_set_master_sync(zns, ifp->ifindex, false, IFINDEX_INTERNAL,
					    DPLANE_INTF_ADMIN_UP, NULL);
}

static void mbfd_guard_schedule(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (zif->mbfd.t_guard)
		return;

	if (zif->mbfd.guard_backoff < ZEBRA_MBFD_GUARD_MIN)
		zif->mbfd.guard_backoff = ZEBRA_MBFD_GUARD_MIN;

	event_add_timer(zrouter.master, mbfd_guard_cb, ifp, zif->mbfd.guard_backoff,
			&zif->mbfd.t_guard);
}

static void mbfd_guard_cb(struct event *t)
{
	struct interface *ifp = EVENT_ARG(t);
	struct zebra_if *zif = ifp->info;

	if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) ||
	    CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH) || !mbfd_admin_up(ifp))
		return;

	zlog_info("micro-BFD: %s set up by someone else while held down, setting it down again",
		  ifp->name);

	SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH | ZEBRA_MBFD_F_WAS_UP);
	if (dplane_intf_set_admin(ifp, false) == ZEBRA_DPLANE_REQUEST_FAILURE)
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);

	zif->mbfd.guard_backoff = MIN(zif->mbfd.guard_backoff * 2, ZEBRA_MBFD_GUARD_MAX);
	mbfd_notify_member(ifp);
}

/*
 * Reconcile a member held down with what the kernel now reports: confirm
 * pending requests, and catch external changes.
 */
static void mbfd_member_kernel_change(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	ifindex_t kbond = mbfd_kernel_bond(ifp);
	ifindex_t home = zif->mbfd.home_bond;
	bool up = if_is_up(ifp);

	if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED))
		return;

	if (kbond != home) {
		/* Taken out of its bond by an operator: no longer ours. */
		zlog_info("micro-BFD: %s left bond ifindex %u while held down, dropping its micro-BFD state",
			  ifp->name, home);
		mbfd_member_clear(zif);
		mbfd_state_write();
		return;
	}

	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
		if (up) {
			/* Release confirmed. */
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("micro-BFD: %s released", ifp->name);
			mbfd_member_clear(zif);
			mbfd_state_write();
		}
		return;
	}

	if (!up) {
		if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH)) {
			/* Hold confirmed. */
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("micro-BFD: %s held down", ifp->name);
			UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);
		}
		return;
	}

	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH))
		return; /* our admin down is not through yet */

	if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED))
		zlog_warn("micro-BFD: %s was set up by someone else while micro-BFD holds it down; setting it down again (remove the lag configuration to release it)",
			  ifp->name);
	SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED);
	mbfd_guard_schedule(ifp);
}

/*
 * LACP actor state poll.
 *
 * The kernel reports a member's LACP actor state with RTM_NEWLINK, but not
 * every change: when a member that stayed in its aggregator goes back to
 * Collecting/Distributing after its partner returns, nothing may be sent,
 * and zebra keeps reporting it not distributing. While a client watches a
 * bond, read the attached members' state from sysfs every second and
 * report changes the kernel didn't. Linux only, and only in zebra's own
 * network namespace (sysfs shows that one).
 */
static bool mbfd_sysfs_uint(const char *path, unsigned int max, unsigned int *val)
{
#ifdef GNU_LINUX
	char buf[16];
	bool ok;
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return false;
	ok = fgets(buf, sizeof(buf), fp) && sscanf(buf, "%u", val) == 1 && *val <= max;
	fclose(fp);
	return ok;
#else
	return false;
#endif
}

static bool mbfd_ad_state_read(const struct interface *ifp, uint8_t *state)
{
	char path[128];
	unsigned int val;

	snprintf(path, sizeof(path), "/sys/class/net/%s/bonding_slave/ad_actor_oper_port_state",
		 ifp->name);
	if (!mbfd_sysfs_uint(path, UINT8_MAX, &val))
		return false;
	*state = val;
	return true;
}

/* The member's 802.3ad aggregator and the bond's active one (standby). */
static bool mbfd_agg_read(const struct interface *ifp, const struct interface *bond, uint16_t *agg,
			  uint16_t *active)
{
	char path[128];
	unsigned int a, b;

	snprintf(path, sizeof(path), "/sys/class/net/%s/bonding_slave/ad_aggregator_id", ifp->name);
	if (!mbfd_sysfs_uint(path, UINT16_MAX, &a))
		return false;
	snprintf(path, sizeof(path), "/sys/class/net/%s/bonding/ad_aggregator", bond->name);
	if (!mbfd_sysfs_uint(path, UINT16_MAX, &b))
		return false;
	*agg = a;
	*active = b;
	return true;
}

static void mbfd_ad_poll_member(struct interface *ifp, void *arg)
{
	struct zebra_if *zif = ifp->info;
	ifindex_t bond = mbfd_kernel_bond(ifp);
	struct interface *bifp;
	uint16_t agg = 0, active = 0;
	bool agg_valid, changed = false;
	uint8_t state;

	if (bond == IFINDEX_INTERNAL || !zif->bondslave_info.ad_actor_state_valid)
		return;
	if (!mbfd_reg_find(mbfd_if_zns(ifp), bond))
		return;

	if (mbfd_ad_state_read(ifp, &state) && state != zif->bondslave_info.ad_actor_oper_state) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("micro-BFD: %s LACP actor state 0x%02x -> 0x%02x (not reported by the kernel)",
				   ifp->name, zif->bondslave_info.ad_actor_oper_state, state);
		zif->bondslave_info.ad_actor_oper_state = state;
		changed = true;
	}

	bifp = if_lookup_by_index_per_ns(mbfd_if_zns(ifp), bond);
	agg_valid = bifp && mbfd_agg_read(ifp, bifp, &agg, &active);
	if (agg_valid != zif->mbfd.agg_valid || agg != zif->mbfd.agg_id ||
	    active != zif->mbfd.active_agg_id) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("micro-BFD: %s aggregator %u, active %u%s", ifp->name, agg,
				   active, agg_valid ? "" : " (unknown)");
		zif->mbfd.agg_valid = agg_valid;
		zif->mbfd.agg_id = agg;
		zif->mbfd.active_agg_id = active;
		changed = true;
	}

	/* Standby only once it lasted (see mbfd_standby_now()). */
	if (!mbfd_standby_now(ifp, bond)) {
		timerclear(&zif->mbfd.standby_since);
		if (zif->mbfd.standby) {
			zif->mbfd.standby = false;
			changed = true;
		}
	} else if (!zif->mbfd.standby) {
		if (!timerisset(&zif->mbfd.standby_since))
			monotime(&zif->mbfd.standby_since);
		else if (monotime_since(&zif->mbfd.standby_since, NULL) / 1000 >=
			 MBFD_STANDBY_STABLE_MS) {
			zif->mbfd.standby = true;
			changed = true;
		}
	}

	if (changed)
		zebra_mbfd_if_update(ifp);
}

static void mbfd_ad_poll_cb(struct event *t)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	if (mbfd_regs_count(&mbfd_regs) == 0)
		return;

	if (zns)
		mbfd_if_walk(zns, mbfd_ad_poll_member, NULL);
	mbfd_ad_poll_schedule();
}

static void mbfd_ad_poll_schedule(void)
{
	if (!event_is_scheduled(t_ad_poll))
		event_add_timer_msec(zrouter.master, mbfd_ad_poll_cb, NULL, MBFD_AD_POLL_MS,
				     &t_ad_poll);
}

/*
 * Kernel interface events
 */
void zebra_mbfd_if_update(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_ns *zns = mbfd_if_zns(ifp);
	struct mbfd_reg *reg;

	if (!zif)
		return;

	if (IS_ZEBRA_IF_BOND(ifp)) {
		reg = mbfd_reg_find(zns, ifp->ifindex);
		if (reg && reg->client) {
			uint8_t mode, count;

			/* Bond came back, changed mode, became an ES, ... */
			if (!reg->status_sent ||
			    mbfd_bond_status(reg, &mode, &count) != reg->status)
				mbfd_reg_resync(reg);
		}
	}

	mbfd_member_kernel_change(ifp);
	mbfd_notify_member(ifp);
}

void zebra_mbfd_if_delete(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_ns *zns = mbfd_if_zns(ifp);
	struct mbfd_reg *reg;
	bool changed = false;

	if (!zif)
		return;

	if (IS_ZEBRA_IF_BOND(ifp)) {
		struct interface *mifp, *tmp;
		struct vrf *vrf;

		/* Detached members of a deleted bond can't go back. */
		RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
			struct zebra_vrf *zvrf = vrf->info;

			if (!zvrf || zvrf->zns != zns)
				continue;
			RB_FOREACH_SAFE (mifp, if_name_head, &vrf->ifaces_by_name, tmp) {
				struct zebra_if *mzif = mifp->info;

				if (mzif && CHECK_FLAG(mzif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) &&
				    mzif->mbfd.home_bond == ifp->ifindex) {
					mbfd_member_clear(mzif);
					changed = true;
				}
				if (mzif && mzif->mbfd.notified_bond == ifp->ifindex)
					mzif->mbfd.notified_bond = IFINDEX_INTERNAL;
			}
		}

		reg = mbfd_reg_find(zns, ifp->ifindex);
		if (reg && reg->client) {
			struct zapi_lag_bond_status st = {
				.bond_ifindex = reg->bond_ifindex,
				.status = ZAPI_LAG_BOND_NOT_FOUND,
				.bond_mode = ZAPI_LAG_BOND_MODE_UNKNOWN,
			};
			struct stream *s = stream_new(ZEBRA_MAX_PACKET_SIZ);

			zapi_lag_bond_status_encode(s, reg->vrf_id, &st);
			zserv_send_message(reg->client, s);
			reg->status = ZAPI_LAG_BOND_NOT_FOUND;
			reg->status_sent = true;
		}
	}

	/* A member going away: tell the client, drop its state. */
	if (zif->mbfd.notified_bond != IFINDEX_INTERNAL) {
		reg = mbfd_reg_active(zns, zif->mbfd.notified_bond);
		if (reg)
			mbfd_send_member(reg, ifp, ZAPI_LAG_MBR_DEL, zif->mbfd.last_flags,
					 zif->mbfd.last_ad_state);
		zif->mbfd.notified_bond = IFINDEX_INTERNAL;
	}
	if (zif->mbfd.flags) {
		mbfd_member_clear(zif);
		changed = true;
	}

	if (changed)
		mbfd_state_write();
}

void zebra_mbfd_dplane_result(struct interface *ifp, bool set_master, bool success)
{
	struct zebra_if *zif = ifp->info;

	if (!zif || success)
		return;

	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
		zlog_warn("micro-BFD: releasing %s failed, it stays held down", ifp->name);
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH);
	} else if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH)) {
		zlog_warn("micro-BFD: holding %s down failed", ifp->name);
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);
		if (if_is_up(ifp))
			mbfd_member_clear(zif);
	} else {
		return;
	}

	mbfd_notify_member(ifp);
	mbfd_state_write();
}

/*
 * ZAPI
 */
struct mbfd_release_arg {
	ifindex_t bond;
	bool reattach;
	bool changed;
};

static void mbfd_release_cb(struct interface *ifp, void *arg)
{
	struct mbfd_release_arg *ra = arg;
	struct zebra_if *zif = ifp->info;

	if (zif->mbfd.notified_bond == ra->bond)
		zif->mbfd.notified_bond = IFINDEX_INTERNAL;

	if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) || zif->mbfd.home_bond != ra->bond)
		return;

	if (ra->reattach) {
		mbfd_member_reattach(ifp);
		ra->changed = true;
	} else {
		/*
		 * Fail-closed: the member stays held down (and guarded); a pending
		 * attach is abandoned.
		 */
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH);
	}
}

/* Drop a registration; release the members it holds down if `reattach`. */
static void mbfd_reg_release(struct mbfd_reg *reg, bool reattach)
{
	struct mbfd_release_arg ra = { .bond = reg->bond_ifindex, .reattach = reattach };

	mbfd_if_walk(reg->zns, mbfd_release_cb, &ra);
	mbfd_regs_del(&mbfd_regs, reg);
	XFREE(MTYPE_ZEBRA_MBFD_REG, reg);
	mbfd_state_write();
}

void zebra_mbfd_register(struct zserv *client, struct zmsghdr *hdr, struct stream *msg,
			 struct zebra_vrf *zvrf)
{
	struct zapi_lag_register zreg;
	struct mbfd_reg *reg;
	struct zebra_ns *zns = zvrf ? zvrf->zns : NULL;

	if (zapi_lag_register_decode(msg, &zreg) < 0 || !zns) {
		zlog_warn("micro-BFD: malformed %s from %s", zserv_command_string(hdr->command),
			  zebra_route_string(client->proto));
		return;
	}

	reg = mbfd_reg_find(zns, zreg.bond_ifindex);

	if (hdr->command == ZEBRA_LAG_MBFD_UNREGISTER) {
		if (!reg || reg->client != client)
			return;
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("micro-BFD: %s unregistered bond ifindex %u",
				   zebra_route_string(client->proto), zreg.bond_ifindex);
		mbfd_reg_release(reg, true);
		return;
	}

	if (!reg) {
		reg = XCALLOC(MTYPE_ZEBRA_MBFD_REG, sizeof(*reg));
		reg->zns = zns;
		reg->bond_ifindex = zreg.bond_ifindex;
		mbfd_regs_add_tail(&mbfd_regs, reg);
		mbfd_ad_poll_schedule();
	} else if (reg->client && reg->client != client) {
		zlog_warn("micro-BFD: bond ifindex %u registered by %s, taking over from %s",
			  zreg.bond_ifindex, zebra_route_string(client->proto),
			  zebra_route_string(reg->client->proto));
	}

	reg->client = client;
	reg->vrf_id = hdr->vrf_id;
	reg->flags = zreg.flags;
	reg->status_sent = false;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("micro-BFD: %s registered bond ifindex %u%s",
			   zebra_route_string(client->proto), zreg.bond_ifindex,
			   CHECK_FLAG(zreg.flags, ZAPI_LAG_REG_F_FAIL_OPEN) ? " (fail-open)"
									    : " (fail-closed)");

	mbfd_reg_resync(reg);
	mbfd_state_write();
}

void zebra_mbfd_dist_set(struct zserv *client, struct zmsghdr *hdr, struct stream *msg,
			 struct zebra_vrf *zvrf)
{
	struct zapi_lag_dist dist;
	struct zebra_ns *zns = zvrf ? zvrf->zns : NULL;
	struct interface *bond, *ifp;
	struct zebra_if *zif;
	struct mbfd_reg *reg;
	uint8_t mode, count;

	if (zapi_lag_dist_decode(msg, &dist) < 0 || !zns) {
		zlog_warn("micro-BFD: malformed %s from %s", zserv_command_string(hdr->command),
			  zebra_route_string(client->proto));
		return;
	}

	reg = mbfd_reg_find(zns, dist.bond_ifindex);
	if (!reg || reg->client != client) {
		zlog_warn("micro-BFD: %s sent a member request for unregistered bond ifindex %u",
			  zebra_route_string(client->proto), dist.bond_ifindex);
		return;
	}

	if (mbfd_bond_status(reg, &mode, &count) != ZAPI_LAG_BOND_OK) {
		zlog_warn("micro-BFD: refusing member request on bond ifindex %u (%s)",
			  dist.bond_ifindex, zapi_lag_bond_status2str(reg->status));
		return;
	}
	bond = mbfd_reg_bond(reg);

	ifp = if_lookup_by_index_per_ns(zns, dist.mbr_ifindex);
	zif = ifp ? ifp->info : NULL;
	if (!zif || mbfd_member_bond(ifp) != dist.bond_ifindex) {
		zlog_warn("micro-BFD: ifindex %u is not a member of %s", dist.mbr_ifindex,
			  bond->name);
		return;
	}

	if (!dist.enable) {
		/* Hold down */
		if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) &&
		    !CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
			mbfd_notify_member(ifp);
			return;
		}

		zlog_info("micro-BFD: holding %s down (bond %s)", ifp->name, bond->name);

		event_cancel(&zif->mbfd.t_guard);
		zif->mbfd.guard_backoff = 0;
		zif->mbfd.home_bond = dist.bond_ifindex;
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH | ZEBRA_MBFD_F_EXT_REENSLAVED |
						    ZEBRA_MBFD_F_WAS_UP);
		SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED);

		/* Already down (the operator's): nothing to do, nothing to undo. */
		if (mbfd_admin_up(ifp)) {
			SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_WAS_UP | ZEBRA_MBFD_F_PEND_DETACH);
			if (dplane_intf_set_admin(ifp, false) == ZEBRA_DPLANE_REQUEST_FAILURE)
				mbfd_member_clear(zif);
		}
	} else {
		/* Release */
		if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) ||
		    CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
			mbfd_notify_member(ifp);
			return;
		}

		zlog_info("micro-BFD: releasing %s (bond %s)", ifp->name, bond->name);

		event_cancel(&zif->mbfd.t_guard);
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);

		if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_WAS_UP) || mbfd_admin_up(ifp)) {
			/* It stays as the operator left it. */
			mbfd_member_clear(zif);
		} else {
			SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH);
			if (dplane_intf_set_admin(ifp, true) == ZEBRA_DPLANE_REQUEST_FAILURE)
				UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH);
		}
	}

	mbfd_notify_member(ifp);
	mbfd_state_write();
}

/* A client went away (including at zebra shutdown): fail open or closed. */
static int mbfd_client_close(struct zserv *client)
{
	struct mbfd_reg *reg;

	frr_each_safe (mbfd_regs, &mbfd_regs, reg) {
		if (reg->client != client)
			continue;

		zlog_info("micro-BFD: %s gone, bond ifindex %u %s",
			  zebra_route_string(client->proto), reg->bond_ifindex,
			  CHECK_FLAG(reg->flags, ZAPI_LAG_REG_F_FAIL_OPEN)
				  ? "fail-open: releasing members held down"
				  : "fail-closed: keeping members held down");
		mbfd_reg_release(reg, CHECK_FLAG(reg->flags, ZAPI_LAG_REG_F_FAIL_OPEN));
	}

	return 0;
}

/*
 * State file: members held down, so that a restarted zebra releases
 * (fail-open) or keeps holding (fail-closed) members it no longer knows
 * about. One line per member: "<member> <bond> <fail-open 0|1> <was-up 0|1>"
 * (an older zebra wrote no was-up: those members were out of the bond).
 */
static void mbfd_state_path(char *buf, size_t len)
{
	snprintf(buf, len, "%s/%s", frr_runstatedir, MBFD_STATE_FILE);
}

static void mbfd_state_write_cb(struct interface *ifp, void *arg)
{
	FILE *fp = arg;
	struct zebra_if *zif = ifp->info;
	struct zebra_ns *zns = mbfd_if_zns(ifp);
	struct interface *bond;
	struct mbfd_reg *reg;

	if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) || !zns)
		return;

	bond = if_lookup_by_index_per_ns(zns, zif->mbfd.home_bond);
	if (!bond)
		return;

	reg = mbfd_reg_find(zns, zif->mbfd.home_bond);
	fprintf(fp, "%s %s %d %d\n", ifp->name, bond->name,
		reg ? !!CHECK_FLAG(reg->flags, ZAPI_LAG_REG_F_FAIL_OPEN) : 0,
		!!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_WAS_UP));
}

static struct interface *mbfd_if_by_name(const char *name)
{
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_name_vrf(name, vrf);
		if (ifp && ifp->info)
			return ifp;
	}

	return NULL;
}

static void mbfd_state_write(void)
{
	char path[MAXPATHLEN], tmp[MAXPATHLEN + 8];
	struct mbfd_saved *sv;
	struct stat st;
	FILE *fp;

	mbfd_state_path(path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	fp = fopen(tmp, "w");
	if (!fp) {
		zlog_warn("micro-BFD: can't write %s: %s", tmp, safe_strerror(errno));
		return;
	}
	mbfd_if_walk(NULL, mbfd_state_write_cb, fp);

	/* Saved lines not handled yet, unless written above already. */
	frr_each (mbfd_saved, &mbfd_saved, sv) {
		struct interface *ifp = mbfd_if_by_name(sv->mname);
		struct zebra_if *zif = ifp ? ifp->info : NULL;

		if (zif && CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED))
			continue;
		fprintf(fp, "%s %s %d %d\n", sv->mname, sv->bname, sv->failopen, sv->was_up);
	}
	fclose(fp);

	if (stat(tmp, &st) == 0 && st.st_size == 0) {
		unlink(tmp);
		unlink(path);
		return;
	}

	if (rename(tmp, path) < 0)
		zlog_warn("micro-BFD: can't rename %s: %s", tmp, safe_strerror(errno));
}

/* At startup: load the state file left by the previous zebra. */
static void mbfd_state_load(void)
{
	char path[MAXPATHLEN], line[128];
	struct mbfd_saved *sv;
	FILE *fp;

	mbfd_state_path(path, sizeof(path));
	fp = fopen(path, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		sv = XCALLOC(MTYPE_ZEBRA_MBFD_SAVED, sizeof(*sv));
		sv->was_up = 1;
		if (sscanf(line, "%16s %16s %d %d", sv->mname, sv->bname, &sv->failopen,
			   &sv->was_up) < 3) {
			XFREE(MTYPE_ZEBRA_MBFD_SAVED, sv);
			continue;
		}
		mbfd_saved_add_tail(&mbfd_saved, sv);
	}
	fclose(fp);
}

/* Act on the saved lines once interfaces are known; retry missing ones. */
static void mbfd_state_read_cb(struct event *t)
{
	bool last = ++state_read_tries >= MBFD_STATE_READ_RETRIES;
	bool unresolved = false;
	struct mbfd_saved *sv;

	frr_each_safe (mbfd_saved, &mbfd_saved, sv) {
		struct interface *mifp = mbfd_if_by_name(sv->mname);
		struct interface *bifp = mbfd_if_by_name(sv->bname);
		struct zebra_if *zif;

		if (!mifp || !bifp || !IS_ZEBRA_IF_BOND(bifp)) {
			if (!last) {
				unresolved = true;
				continue;
			}
			zlog_warn("micro-BFD: saved state for %s (bond %s) dropped: interface not found",
				  sv->mname, sv->bname);
			goto done;
		}

		zif = mifp->info;
		if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED))
			goto done; /* already known (a client re-registered first) */

		if (sv->failopen) {
			if (mbfd_kernel_bond(mifp) != bifp->ifindex) {
				zlog_info("micro-BFD: %s was out of %s before zebra restarted, re-attaching it (fail-open)",
					  mifp->name, bifp->name);
				dplane_intf_set_master(mifp, bifp, mbfd_enslave_flags(mifp));
			} else if (sv->was_up && !mbfd_admin_up(mifp)) {
				zlog_info("micro-BFD: %s was held down before zebra restarted, setting it up (fail-open)",
					  mifp->name);
				dplane_intf_set_admin(mifp, true);
			}
		} else if (mbfd_kernel_bond(mifp) == bifp->ifindex) {
			zlog_info("micro-BFD: %s was held down before zebra restarted, keeping it down (fail-closed)",
				  mifp->name);
			zif->mbfd.home_bond = bifp->ifindex;
			SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED);
			if (sv->was_up)
				SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_WAS_UP);
			if (mbfd_admin_up(mifp)) {
				SET_FLAG(zif->mbfd.flags,
					 ZEBRA_MBFD_F_PEND_DETACH | ZEBRA_MBFD_F_WAS_UP);
				dplane_intf_set_admin(mifp, false);
			}
			mbfd_notify_member(mifp);
		} else {
			zlog_info("micro-BFD: %s was out of %s before zebra restarted, putting it back held down (fail-closed)",
				  mifp->name, bifp->name);
			zif->mbfd.home_bond = bifp->ifindex;
			SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED | ZEBRA_MBFD_F_WAS_UP |
							  ZEBRA_MBFD_F_PEND_DETACH);
			dplane_intf_set_master(mifp, bifp,
					       DPLANE_INTF_MASTER_F_DOWN_FIRST |
						       DPLANE_INTF_MASTER_F_DOWN_AFTER);
			mbfd_notify_member(mifp);
		}
done:
		mbfd_saved_del(&mbfd_saved, sv);
		XFREE(MTYPE_ZEBRA_MBFD_SAVED, sv);
	}

	if (unresolved)
		event_add_timer(zrouter.master, mbfd_state_read_cb, NULL, MBFD_STATE_READ_DELAY,
				&t_state_read);

	mbfd_state_write();
}

/*
 * "show interface"
 */
void zebra_mbfd_if_show(struct vty *vty, json_object *json_if, struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_ns *zns = mbfd_if_zns(ifp);
	struct mbfd_reg *reg = IS_ZEBRA_IF_BOND(ifp) ? mbfd_reg_find(zns, ifp->ifindex) : NULL;
	char buf[128];

	if (reg) {
		const char *client = reg->client ? zebra_route_string(reg->client->proto) : "none";
		bool fo = CHECK_FLAG(reg->flags, ZAPI_LAG_REG_F_FAIL_OPEN);

		if (json_if) {
			json_object *jo = json_object_new_object();

			json_object_string_add(jo, "client", client);
			json_object_string_add(jo, "status", zapi_lag_bond_status2str(reg->status));
			json_object_boolean_add(jo, "failOpen", fo);
			json_object_object_add(json_if, "microBfdBond", jo);
		} else {
			vty_out(vty, "  micro-BFD: registered by %s, status %s, %s\n", client,
				zapi_lag_bond_status2str(reg->status),
				fo ? "fail-open" : "fail-closed");
		}
	}

	if (!zif || (!zif->mbfd.flags && zif->mbfd.notified_bond == IFINDEX_INTERNAL))
		return;

	if (json_if) {
		json_object *jo = json_object_new_object();

		json_object_int_add(jo, "bondIfindex", mbfd_member_bond(ifp));
		json_object_boolean_add(jo, "heldDown",
					CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED));
		json_object_boolean_add(jo, "wasUp",
					CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_WAS_UP));
		json_object_boolean_add(jo, "pending",
					CHECK_FLAG(zif->mbfd.flags,
						   ZEBRA_MBFD_F_PEND_DETACH |
							   ZEBRA_MBFD_F_PEND_ATTACH));
		json_object_boolean_add(jo, "setUpExternally",
					CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED));
		json_object_string_add(jo, "reportedFlags",
				       zif->mbfd.notified_bond
					       ? zapi_lag_mbr_flags2str(zif->mbfd.last_flags, buf,
									sizeof(buf))
					       : "");
		json_object_object_add(json_if, "microBfdMember", jo);
	} else {
		vty_out(vty, "  micro-BFD member of bond ifindex %u%s%s%s, reported: %s\n",
			mbfd_member_bond(ifp),
			CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED)
				? ", held down by micro-BFD"
				: "",
			CHECK_FLAG(zif->mbfd.flags,
				   ZEBRA_MBFD_F_PEND_DETACH | ZEBRA_MBFD_F_PEND_ATTACH)
				? ", pending"
				: "",
			CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED)
				? ", set up externally"
				: "",
			zif->mbfd.notified_bond
				? zapi_lag_mbr_flags2str(zif->mbfd.last_flags, buf, sizeof(buf))
				: "-");
	}
}

void zebra_mbfd_init(void)
{
	mbfd_regs_init(&mbfd_regs);
	mbfd_saved_init(&mbfd_saved);
	mbfd_state_load();
	hook_register(zserv_client_close, mbfd_client_close);
	event_add_timer(zrouter.master, mbfd_state_read_cb, NULL, MBFD_STATE_READ_DELAY,
			&t_state_read);
}

void zebra_mbfd_finish(void)
{
	struct mbfd_reg *reg;
	struct mbfd_saved *sv;

	event_cancel(&t_state_read);
	event_cancel(&t_ad_poll);
	while ((sv = mbfd_saved_pop(&mbfd_saved)))
		XFREE(MTYPE_ZEBRA_MBFD_SAVED, sv);
	mbfd_saved_fini(&mbfd_saved);
	hook_unregister(zserv_client_close, mbfd_client_close);

	/* Clients were closed (and failed open) already; drop leftovers. */
	while ((reg = mbfd_regs_pop(&mbfd_regs)))
		XFREE(MTYPE_ZEBRA_MBFD_REG, reg);
	mbfd_regs_fini(&mbfd_regs);
}
