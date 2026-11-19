// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD over the bond (BLB) together with RFC 7130 micro-BFD.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#ifndef _BFD_BLB_H_
#define _BFD_BLB_H_

#include "lib/json.h"
#include "lib/vty.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bfd_session;
struct bfd_lag;

/*
 * "bundle coexistence bob-blb": how a BLB session (a single-hop BFD session
 * on a bond that runs micro-BFD) lives with the bond's micro-BFD sessions.
 * The values match the YANG enum.
 */
enum bfd_blb_mode {
	BFD_BLB_MODE_NONE = 0, /* not configured: BLB runs as a plain session */
	/*
	 * BLB runs as its own session on UDP 3784 and is reported unchanged;
	 * bfdd warns when its detection time leaves micro-BFD too little time
	 * to take a failed member out first.
	 */
	BFD_BLB_MODE_LOGICAL = 1,
};

/*
 * Timer rule (logical mode): BLB detection >= 2 x micro-BFD detection +
 * BFD_BLB_MARGIN_MS. The worst case for BLB riding on a silently failed
 * member is micro-BFD detection, the hold and rehash (10-30 ms), one BLB
 * interval until its next packet takes a good member, and peer skew.
 */
#define BFD_BLB_MARGIN_MS 100

/* Per-session state (struct bfd_session::blb). */
struct bfd_blb_state {
	bool too_fast;	    /* the rule is broken (last check) */
	uint32_t detect_ms; /* BLB detection time the warning was logged for */
	uint32_t need_ms;   /* minimum it was logged against */
};

void bfd_blb_init(void);
void bfd_blb_terminate(void);

/* Configuration (northbound). */
void bfd_blb_set_mode(enum bfd_blb_mode mode);
enum bfd_blb_mode bfd_blb_get_mode(void);
const char *bfd_blb_mode2str(enum bfd_blb_mode mode);

/* Events: re-check the rule (soon, once for all bonds). */
void bfd_blb_changed(void);
void bfd_blb_session_changed(const struct bfd_session *bs);

/* The bond a BLB session runs on, NULL if it isn't one. */
struct bfd_lag *bfd_blb_session_lag(const struct bfd_session *bs);

/* Show. */
void bfd_blb_show_lag(struct vty *vty, const struct bfd_lag *lag, json_object *jl);
void bfd_blb_show_peer(struct vty *vty, const struct bfd_session *bs, json_object *jo);

#ifdef __cplusplus
}
#endif

#endif /* _BFD_BLB_H_ */
