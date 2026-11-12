// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RFC 7130 micro-BFD: BFD on LAG (bond) member links.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#ifndef _BFD_LAG_H_
#define _BFD_LAG_H_

#include "lib/if.h"
#include "lib/json.h"
#include "lib/typesafe.h"
#include "lib/vty.h"
#include "lib/zclient.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bfd_session;
struct bfd_vrf_global;

/* RFC 7130, Section 2.2: UDP destination port of micro-BFD control packets. */
#define BFD_LAG_PORT 6784

/*
 * SO_PRIORITY of micro-BFD frames: 6 like bfdd's other sockets (the band
 * pfifo_fast serves first). 7 would need CAP_NET_ADMIN, which bfdd doesn't
 * hold.
 */
#define BFD_LAG_SOCK_PRIO 6

/* Session name (key bfdname) prefix: "lag:<bond>". */
#define BFD_LAG_NAME_PREFIX "lag:"

/* Defaults, milliseconds. */
#define BFD_LAG_ENABLE_GRACE_DEF    3000
#define BFD_LAG_ADMIN_DOWN_HOLD_DEF 0 /* keep the member as long as AdminDown lasts */
#define BFD_LAG_MAX_SETUP_DEF	    0 /* distributing-only: wait for the sessions forever */

/*
 * RFC 7130, Section 3: a member's sessions run while it distributes. One
 * that stops distributing (LACP took it out) has them deleted only if it
 * still isn't distributing this much later (milliseconds), so a short LACP
 * blip doesn't restart them.
 */
#define BFD_LAG_DIST_STOP_DELAY 1000

/*
 * A member micro-BFD put back (set up again) needs LACP to negotiate before
 * it distributes, and only then do its sessions start, on both ends (RFC
 * 7130, Section 3). It gets BFD_LAG_SETTLE_MAX to distribute (or, strict,
 * be standby), then BFD_LAG_SETTLE_UP (strict: at least enable-grace) for
 * the sessions to come Up. Milliseconds.
 */
#define BFD_LAG_SETTLE_MAX 20000
#define BFD_LAG_SETTLE_UP  3000

/*
 * Recovery probe: a member micro-BFD holds down runs no sessions (RFC 7130,
 * Section 3), so nothing tells when its link works again. After
 * recovery-probe-time it is set up again on probation; if its sessions
 * don't come Up, it is held down again and the wait doubles, up to
 * recovery-probe-max. The wait goes back to recovery-probe-time once the
 * member has stayed in with its sessions Up for BFD_LAG_PROBE_STABLE.
 * Milliseconds.
 */
#define BFD_LAG_RECOVERY_PROBE_DEF     3000
#define BFD_LAG_RECOVERY_PROBE_MAX_DEF 120000
#define BFD_LAG_PROBE_STABLE	       60000

/* A detach/attach request zebra hasn't answered is retried after this (ms). */
#define BFD_LAG_REQ_TIMEOUT 5000

/* After zebra reconnects, members it no longer reports are dropped (ms). */
#define BFD_LAG_STALE_TIMEOUT 5000

/* A source address that disappears is given up only after this (ms). */
#define BFD_LAG_ADDR_CHECK 3000

/*
 * A member held down is released when no session can run only once that
 * lasts this long (ms): a bfdd starting with members zebra kept down
 * (failure-mode closed) learns the bond's addresses some time after them.
 */
#define BFD_LAG_HELD_NOSES_DELAY 10000

/* shutdown: interval of the AdminDown packets on new sessions (ms). */
#define BFD_LAG_ADMIN_DOWN_TX 1000

/* Detection times below this are warned about (milliseconds). */
#define BFD_LAG_MIN_DETECT_WARN 150

enum bfd_lag_mode {
	/*
	 * Sessions on distributing and standby members; a member is held down
	 * when its sessions aren't Up.
	 */
	BFD_LAG_MODE_STRICT = 0,
	/*
	 * Sessions on distributing members only; LACP admits members,
	 * micro-BFD only holds failed ones down.
	 */
	BFD_LAG_MODE_DIST_ONLY = 1,
};

/*
 * What zebra does with the members bfdd took out when bfdd goes away
 * (crash or stop): put them back (open) or keep them out until bfdd
 * returns (closed). Removing the configuration always puts them back.
 */
enum bfd_lag_fail_mode {
	BFD_LAG_FAIL_OPEN = 0,
	BFD_LAG_FAIL_CLOSED,
};

/* Address families a LAG runs micro-BFD in, one session each per member. */
enum bfd_lag_af {
	BFD_LAG_AF_IPV4 = 0,
	BFD_LAG_AF_IPV6,
	BFD_LAG_AF_MAX,
};

union bfd_lag_addr {
	struct in_addr v4;
	struct in6_addr v6;
};

/* Configuration and state of one address family of a LAG. */
struct bfd_lag_af_cfg {
	bool use;
	bool has_dest;
	union bfd_lag_addr dest;
	bool has_src;
	union bfd_lag_addr src;
	/* Source address in use (all zero: none). */
	union bfd_lag_addr local;
	/* "can't run" logged (A3). */
	bool warned;
};

struct bfd_lag_member_stats {
	uint64_t rx_frames;	 /* frames read from the member sockets */
	uint64_t rx_bad_frame;	 /* not a well-formed IP/UDP frame */
	uint64_t rx_mismatch;	 /* wrong addresses or port for this LAG */
	uint64_t rx_wrong_discr; /* Your Discriminator of another session */
	uint64_t rx_no_session;	 /* no session running on the member */
	uint64_t tx_frames;
	uint64_t tx_errors;
	uint64_t detach_count;
	uint64_t attach_count;
	uint64_t probe_count;
};

PREDECL_DLIST(bfd_lag_members);
struct bfd_lag;
struct bfd_lag_member;

/* The micro-BFD session of one address family on a member. */
struct bfd_lag_msess {
	struct bfd_lag_member *m;
	enum bfd_lag_af af;
	struct bfd_session *bs;
	int port_sock; /* keeps the session's UDP source port reserved */
	uint16_t sport;
	struct event *t_read;
	bool peer_admin_down;
	/* admin-down-hold: when AdminDown came, and whether the hold is over. */
	struct timeval admin_down_at;
	bool admin_hold_expired;
	struct event *t_admin_hold;
};

struct bfd_lag_member {
	struct bfd_lag_members_item item;
	struct bfd_lag *lag;

	/* As zebra reports it. */
	ifindex_t ifindex;
	char name[IFNAMSIZ];
	uint8_t mac[ETH_ALEN];
	uint16_t zflags; /* ZAPI_LAG_MBR_F_* */
	uint8_t ad_state;
	bool stale; /* not reported again since zebra reconnected */

	struct bfd_lag_msess s[BFD_LAG_AF_MAX];

	/* Strict mode. */
	bool in_grace;
	struct event *t_grace;
	bool settling;
	struct event *t_settle;
	bool req_outstanding;
	bool req_attach;
	struct event *t_req;
	const char *reason;
	struct timeval last_action;
	bool settle_dist;	/* settling: distributing (or standby) again */
	bool probing;		/* put back by the recovery probe */
	uint32_t probe_wait;	/* next probe after this (ms), 0: not set */
	struct timeval held_at; /* held down since */
	struct event *t_probe;
	struct event *t_stable; /* in, sessions Up: wait reset after this */
	/* held down while no session can run: since when */
	struct timeval noses_since;
	struct event *t_noses;
	/* shutdown: AdminDown sent every second (bfdd's own timers stop) */
	struct event *t_admtx;
	/* down because the peer said so: wait for the peer to act first */
	bool nbr_wait_done;
	struct event *t_nbr_wait;

	/* distributing-only. */
	bool sess_active;   /* sessions started */
	bool ever_up;	    /* all came Up since they started */
	bool setup_expired; /* max-setup-time over before they did */
	struct event *t_setup;
	struct event *t_dist_stop;

	struct bfd_lag_member_stats stats;
};
DECLARE_DLIST(bfd_lag_members, struct bfd_lag_member, item);

PREDECL_DLIST(bfd_lags);
struct bfd_lag {
	struct bfd_lags_item item;

	/* Configuration. */
	char name[IFNAMSIZ]; /* bond interface name */
	struct bfd_lag_af_cfg af[BFD_LAG_AF_MAX];
	bool admin_down;
	char *profile_name;
	enum bfd_lag_mode mode;
	uint32_t enable_grace; /* ms */
	uint32_t max_setup;    /* ms, distributing-only, 0: off */
	uint32_t recovery_probe;     /* ms, 0: off */
	uint32_t recovery_probe_max; /* ms */
	enum bfd_lag_fail_mode fail_mode;
	uint32_t admin_down_hold; /* ms, 0: as long as AdminDown lasts */
	bool fail_mode_warned;	  /* "open on a balance-xor bond" logged */

	/* Bond, once it exists. */
	ifindex_t ifindex;
	vrf_id_t vrf_id;

	/* Zebra. */
	bool registered;
	ifindex_t registered_ifindex;
	bool status_known;
	uint8_t status;	   /* enum zapi_lag_bond_status_code */
	uint8_t bond_mode; /* kernel bond mode */
	struct event *t_stale;
	struct event *t_addr;
	struct event *t_warn; /* A3 warning, if a family still can't run */

	struct bfd_lag_members_head members;
};
DECLARE_DLIST(bfd_lags, struct bfd_lag, item);

/* Daemon life cycle. */
void bfd_lag_init(void);
void bfd_lag_terminate(void);

/* Configuration (northbound). */
struct bfd_lag *bfd_lag_new(const char *name);
struct bfd_lag *bfd_lag_find(const char *name);
void bfd_lag_free(struct bfd_lag *lag);
void bfd_lag_free_all(void);
void bfd_lag_set_use(struct bfd_lag *lag, enum bfd_lag_af af, bool use);
void bfd_lag_set_dest(struct bfd_lag *lag, enum bfd_lag_af af, const union bfd_lag_addr *addr);
void bfd_lag_set_source(struct bfd_lag *lag, enum bfd_lag_af af, const union bfd_lag_addr *addr);
void bfd_lag_set_admin_down(struct bfd_lag *lag, bool admin_down);
void bfd_lag_set_profile(struct bfd_lag *lag, const char *profile);
void bfd_lag_set_mode(struct bfd_lag *lag, enum bfd_lag_mode mode);
void bfd_lag_set_enable_grace(struct bfd_lag *lag, uint32_t ms);
void bfd_lag_set_max_setup(struct bfd_lag *lag, uint32_t ms);
void bfd_lag_set_recovery_probe(struct bfd_lag *lag, uint32_t ms);
void bfd_lag_set_recovery_probe_max(struct bfd_lag *lag, uint32_t ms);
void bfd_lag_set_fail_mode(struct bfd_lag *lag, enum bfd_lag_fail_mode mode);
void bfd_lag_set_admin_down_hold(struct bfd_lag *lag, uint32_t ms);
void bfd_lag_apply(struct bfd_lag *lag);

/* Zebra events (ptm_adapter.c). */
void bfd_lag_zebra_connected(void);
void bfd_lag_zebra_bond_status(vrf_id_t vrf_id, const struct zapi_lag_bond_status *st);
void bfd_lag_zebra_member(vrf_id_t vrf_id, const struct zapi_lag_member *zm);
void bfd_lag_if_add(struct interface *ifp);
void bfd_lag_if_del(struct interface *ifp);
void bfd_lag_if_address(struct interface *ifp);

/* Session hooks (bfd.c, bfd_packet.c, ptm_adapter.c). */
int bfd_lag_session_enable(struct bfd_session *bs);
void bfd_lag_session_disable(struct bfd_session *bs);
void bfd_lag_session_freed(struct bfd_session *bs);
int bfd_lag_send(struct bfd_session *bs, const void *data, size_t len);
void bfd_lag_session_notify(struct bfd_session *bs, uint8_t state);
const char *bfd_lag_session_lag_name(const struct bfd_session *bs);

/* Northbound operational state. */
const struct bfd_lag *bfd_lag_next(const struct bfd_lag *lag);
const struct bfd_lag_member *bfd_lag_member_next(const struct bfd_lag *lag,
						 const struct bfd_lag_member *m);
const struct bfd_lag_member *bfd_lag_member_find(const struct bfd_lag *lag, const char *ifname);
const struct bfd_session *bfd_lag_member_session(const struct bfd_lag_member *m,
						 enum bfd_lag_af af);
bool bfd_lag_member_detached(const struct bfd_lag_member *m);
bool bfd_lag_member_distributing(const struct bfd_lag_member *m);
bool bfd_lag_member_standby(const struct bfd_lag_member *m);
void bfd_lag_session_counts(enum bfd_lag_af af, uint32_t *total, uint32_t *up, uint32_t *down,
			    uint32_t *admin_down);

/* Show. */
void bfd_lag_show(struct vty *vty, const char *name, bool use_json);
void bfd_lag_show_statistics(struct vty *vty, bool use_json);
void bfd_lag_vrf_disable(struct bfd_vrf_global *bvrf);

const char *bfd_lag_mode2str(enum bfd_lag_mode mode);
const char *bfd_lag_fail_mode2str(enum bfd_lag_fail_mode mode);

#ifdef __cplusplus
}
#endif

#endif /* _BFD_LAG_H_ */
