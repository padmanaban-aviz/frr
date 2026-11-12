// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra RFC 7130 micro-BFD support: bond (LAG) member tracking and control.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#ifndef _ZEBRA_MBFD_H
#define _ZEBRA_MBFD_H

#include "lib/zclient.h"
#include "lib/json.h"

#ifdef __cplusplus
extern "C" {
#endif

struct zserv;
struct zmsghdr;
struct zebra_vrf;
struct interface;
struct vty;

/* struct zebra_mbfd_mbr flags */
#define ZEBRA_MBFD_F_DETACHED	    0x01 /* held down by micro-BFD */
#define ZEBRA_MBFD_F_PEND_DETACH    0x02 /* admin down requested, not seen yet */
#define ZEBRA_MBFD_F_PEND_ATTACH    0x04 /* admin up requested, not seen yet */
#define ZEBRA_MBFD_F_EXT_REENSLAVED 0x08 /* set up by someone else while held down */
#define ZEBRA_MBFD_F_WAS_UP	    0x10 /* admin up when held down: zebra set it down */

/* Guard against a member held down being set up by someone else, seconds. */
#define ZEBRA_MBFD_GUARD_MIN 1
#define ZEBRA_MBFD_GUARD_MAX 30

/* Kernel bond modes micro-BFD supports. */
#define ZEBRA_BOND_MODE_XOR    2 /* balance-xor */
#define ZEBRA_BOND_MODE_8023AD 4 /* 802.3ad (LACP) */

extern void zebra_mbfd_init(void);
extern void zebra_mbfd_finish(void);

/* ZAPI handlers */
extern void zebra_mbfd_register(struct zserv *client, struct zmsghdr *hdr, struct stream *msg,
				struct zebra_vrf *zvrf);
extern void zebra_mbfd_dist_set(struct zserv *client, struct zmsghdr *hdr, struct stream *msg,
				struct zebra_vrf *zvrf);

/* Kernel interface events (interface.c) */
extern void zebra_mbfd_if_update(struct interface *ifp);
extern void zebra_mbfd_if_delete(struct interface *ifp);
extern void zebra_mbfd_dplane_result(struct interface *ifp, bool set_master, bool success);

/* "show interface" */
extern void zebra_mbfd_if_show(struct vty *vty, json_object *json_if, struct interface *ifp);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_MBFD_H */
