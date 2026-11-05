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
 * - ZEBRA_LAG_MBFD_DIST_SET: take a member out of the bond (detach) or put
 *   it back (attach).
 *
 * Detach releases the member from the bond, then sets it up again so its
 * micro-BFD session keeps running (the bonding driver closes a released
 * member). Attach sets the member down and enslaves it in one request (the
 * bonding driver refuses an up interface). While detached, the member stays
 * a "logical" member here (zebra_if->mbfd.home_bond), and is still
 * reported to the client.
 *
 * Fail-open: when the client unregisters or goes away (including zebra's own
 * shutdown, which closes clients first), detached members are re-attached,
 * unless the bond was registered without ZAPI_LAG_REG_F_FAIL_OPEN. Detached
 * members are recorded in a state file so a restarted zebra can re-attach
 * (fail-open) or keep (fail-closed) them.
 *
 * If something else (an operator, NetworkManager, ...) re-enslaves a
 * member micro-BFD keeps detached, zebra releases it again with back-off.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#include <zebra.h>
#include <sys/stat.h>

#include "lib/if.h"
#include "lib/libfrr.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include "lib/vty.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rt.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_mbfd.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_MBFD_REG, "micro-BFD bond registration");

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
static struct event *t_state_read;
static unsigned int state_read_tries;

#define MBFD_STATE_FILE		"zebra_mbfd.state"
#define MBFD_STATE_READ_DELAY	5 /* seconds after startup */
#define MBFD_STATE_READ_RETRIES 6

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

/* Put a member micro-BFD detached back into its bond (fail-open). */
static void mbfd_member_reattach(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_ns *zns = mbfd_if_zns(ifp);
	ifindex_t home = zif->mbfd.home_bond;
	struct interface *bond = zns ? if_lookup_by_index_per_ns(zns, home) : NULL;

	mbfd_member_clear(zif);

	if (!bond || !IS_ZEBRA_IF_BOND(bond) || mbfd_kernel_bond(ifp) == home)
		return;

	zlog_info("micro-BFD: re-attaching %s to %s (fail-open)", ifp->name, bond->name);

	if (dplane_intf_set_master(ifp, bond, DPLANE_INTF_MASTER_F_DOWN_FIRST) ==
		    ZEBRA_DPLANE_REQUEST_FAILURE &&
	    zns)
		/* Dataplane gone (late in shutdown): do it synchronously. */
		kernel_intf_set_master_sync(zns, ifp->ifindex, true, bond->ifindex,
					    DPLANE_INTF_ADMIN_DOWN, NULL);
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
	    CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH) ||
	    mbfd_kernel_bond(ifp) != zif->mbfd.home_bond)
		return;

	zlog_info("micro-BFD: %s re-enslaved by someone else, releasing it again", ifp->name);

	SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);
	if (dplane_intf_release_master(ifp, true, NULL) == ZEBRA_DPLANE_REQUEST_FAILURE)
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);

	zif->mbfd.guard_backoff = MIN(zif->mbfd.guard_backoff * 2, ZEBRA_MBFD_GUARD_MAX);
	mbfd_notify_member(ifp);
}

/*
 * Reconcile a detached member with what the kernel now reports: confirm
 * pending requests, and catch external changes.
 */
static void mbfd_member_kernel_change(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	ifindex_t kbond = mbfd_kernel_bond(ifp);
	ifindex_t home = zif->mbfd.home_bond;

	if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED))
		return;

	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
		if (kbond == home) {
			/* Attach confirmed. */
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("micro-BFD: %s attached to bond ifindex %u", ifp->name,
					   home);
			mbfd_member_clear(zif);
			mbfd_state_write();
		}
		return;
	}

	if (kbond == IFINDEX_INTERNAL) {
		if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH)) {
			/* Detach confirmed. */
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("micro-BFD: %s detached from bond ifindex %u",
					   ifp->name, home);
			UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);
		}
		return;
	}

	if (kbond == home) {
		if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH))
			return; /* our release is not through yet */

		if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED))
			zlog_warn("micro-BFD: %s was put back into its bond by someone else while micro-BFD keeps it detached; releasing it again (check NetworkManager / systemd-networkd / ifupdown)",
				  ifp->name);
		SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED);
		mbfd_guard_schedule(ifp);
		return;
	}

	/* Moved to another bond by an operator: no longer ours. */
	zlog_info("micro-BFD: %s moved from bond ifindex %u to ifindex %u, dropping its micro-BFD state",
		  ifp->name, home, kbond);
	mbfd_member_clear(zif);
	mbfd_state_write();
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

	/* Only the master change itself matters, not the follow-up up/MAC. */
	if (!zif || success || !set_master)
		return;

	if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
		zlog_warn("micro-BFD: attaching %s failed, it stays detached", ifp->name);
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH);
	} else if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH)) {
		zlog_warn("micro-BFD: detaching %s failed", ifp->name);
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);
		if (mbfd_kernel_bond(ifp) == zif->mbfd.home_bond)
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
		 * Fail-closed: the member stays detached (and guarded); a pending
		 * attach is abandoned.
		 */
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH);
	}
}

/* Drop a registration; re-attach its detached members if `reattach`. */
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
		/* Detach */
		if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) &&
		    !CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
			mbfd_notify_member(ifp);
			return;
		}

		zlog_info("micro-BFD: detaching %s from %s", ifp->name, bond->name);

		event_cancel(&zif->mbfd.t_guard);
		zif->mbfd.home_bond = dist.bond_ifindex;
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH | ZEBRA_MBFD_F_EXT_REENSLAVED);
		SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED);

		if (mbfd_kernel_bond(ifp) == dist.bond_ifindex) {
			const uint8_t *mac = NULL;

			if (CHECK_FLAG(dist.flags, ZAPI_LAG_DIST_F_RESTORE_MAC) &&
			    bond->hw_addr_len == ETH_ALEN)
				mac = bond->hw_addr;

			SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);
			if (dplane_intf_release_master(ifp, true, mac) ==
			    ZEBRA_DPLANE_REQUEST_FAILURE)
				mbfd_member_clear(zif);
		}
	} else {
		/* Attach */
		if (!CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) ||
		    CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH)) {
			mbfd_notify_member(ifp);
			return;
		}

		zlog_info("micro-BFD: attaching %s to %s", ifp->name, bond->name);

		event_cancel(&zif->mbfd.t_guard);
		UNSET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_DETACH);

		if (mbfd_kernel_bond(ifp) == dist.bond_ifindex) {
			mbfd_member_clear(zif);
		} else {
			SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_PEND_ATTACH);
			if (dplane_intf_set_master(ifp, bond, DPLANE_INTF_MASTER_F_DOWN_FIRST) ==
			    ZEBRA_DPLANE_REQUEST_FAILURE)
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
				  ? "fail-open: re-attaching detached members"
				  : "fail-closed: keeping detached members out");
		mbfd_reg_release(reg, CHECK_FLAG(reg->flags, ZAPI_LAG_REG_F_FAIL_OPEN));
	}

	return 0;
}

/*
 * State file: detached members, so that a restarted zebra re-attaches
 * (fail-open) or keeps out (fail-closed) members it no longer knows about.
 * One line per member: "<member> <bond> <fail-open 0|1>".
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
	fprintf(fp, "%s %s %d\n", ifp->name, bond->name,
		reg ? !!CHECK_FLAG(reg->flags, ZAPI_LAG_REG_F_FAIL_OPEN) : 0);
}

static void mbfd_state_write(void)
{
	char path[MAXPATHLEN], tmp[MAXPATHLEN + 8];
	struct stat st;
	FILE *fp;

	/* Don't let a write wipe out a state file not yet read at startup. */
	if (t_state_read)
		return;

	mbfd_state_path(path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	fp = fopen(tmp, "w");
	if (!fp) {
		zlog_warn("micro-BFD: can't write %s: %s", tmp, safe_strerror(errno));
		return;
	}
	mbfd_if_walk(NULL, mbfd_state_write_cb, fp);
	fclose(fp);

	if (stat(tmp, &st) == 0 && st.st_size == 0) {
		unlink(tmp);
		unlink(path);
		return;
	}

	if (rename(tmp, path) < 0)
		zlog_warn("micro-BFD: can't rename %s: %s", tmp, safe_strerror(errno));
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

static void mbfd_state_read_cb(struct event *t)
{
	char path[MAXPATHLEN], line[128], mname[IFNAMSIZ + 1], bname[IFNAMSIZ + 1];
	bool unresolved = false;
	int failopen;
	FILE *fp;

	mbfd_state_path(path, sizeof(path));
	fp = fopen(path, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		struct interface *mifp, *bifp;
		struct zebra_if *zif;

		if (sscanf(line, "%16s %16s %d", mname, bname, &failopen) != 3)
			continue;

		mifp = mbfd_if_by_name(mname);
		bifp = mbfd_if_by_name(bname);
		if (!mifp || !bifp || !IS_ZEBRA_IF_BOND(bifp)) {
			unresolved = true;
			continue;
		}

		zif = mifp->info;
		if (CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED))
			continue; /* already known (a client re-registered first) */

		if (failopen) {
			if (mbfd_kernel_bond(mifp) != bifp->ifindex) {
				zlog_info("micro-BFD: %s was detached before zebra restarted, re-attaching it to %s (fail-open)",
					  mifp->name, bifp->name);
				dplane_intf_set_master(mifp, bifp, DPLANE_INTF_MASTER_F_DOWN_FIRST);
			}
		} else {
			zlog_info("micro-BFD: %s was detached before zebra restarted, keeping it out of %s (fail-closed)",
				  mifp->name, bifp->name);
			zif->mbfd.home_bond = bifp->ifindex;
			SET_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED);
			mbfd_member_kernel_change(mifp);
			mbfd_notify_member(mifp);
		}
	}
	fclose(fp);

	if (unresolved && ++state_read_tries < MBFD_STATE_READ_RETRIES) {
		event_add_timer(zrouter.master, mbfd_state_read_cb, NULL, MBFD_STATE_READ_DELAY,
				&t_state_read);
		return;
	}

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
		json_object_boolean_add(jo, "detached",
					CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED));
		json_object_boolean_add(jo, "pending",
					CHECK_FLAG(zif->mbfd.flags,
						   ZEBRA_MBFD_F_PEND_DETACH |
							   ZEBRA_MBFD_F_PEND_ATTACH));
		json_object_boolean_add(jo, "extReenslaved",
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
			CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_DETACHED) ? ", detached" : "",
			CHECK_FLAG(zif->mbfd.flags,
				   ZEBRA_MBFD_F_PEND_DETACH | ZEBRA_MBFD_F_PEND_ATTACH)
				? ", pending"
				: "",
			CHECK_FLAG(zif->mbfd.flags, ZEBRA_MBFD_F_EXT_REENSLAVED)
				? ", re-enslaved externally"
				: "",
			zif->mbfd.notified_bond
				? zapi_lag_mbr_flags2str(zif->mbfd.last_flags, buf, sizeof(buf))
				: "-");
	}
}

void zebra_mbfd_init(void)
{
	mbfd_regs_init(&mbfd_regs);
	hook_register(zserv_client_close, mbfd_client_close);
	event_add_timer(zrouter.master, mbfd_state_read_cb, NULL, MBFD_STATE_READ_DELAY,
			&t_state_read);
}

void zebra_mbfd_finish(void)
{
	struct mbfd_reg *reg;

	event_cancel(&t_state_read);
	hook_unregister(zserv_client_close, mbfd_client_close);

	/* Clients were closed (and failed open) already; drop leftovers. */
	while ((reg = mbfd_regs_pop(&mbfd_regs)))
		XFREE(MTYPE_ZEBRA_MBFD_REG, reg);
	mbfd_regs_fini(&mbfd_regs);
}
