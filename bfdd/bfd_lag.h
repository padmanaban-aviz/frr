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
#define BFD_LAG_ENABLE_GRACE_DEF 3000
#define BFD_LAG_HOLD_UP_DEF	 0

/*
 * A re-attached member bounces its link: the bonding driver needs it down
 * to enslave it. Session Down is ignored until the member distributes with
 * its session Up again, for at most this long (milliseconds).
 */
#define BFD_LAG_SETTLE_MAX 10000

/* A detach/attach request zebra hasn't answered is retried after this (ms). */
#define BFD_LAG_REQ_TIMEOUT 5000

/* After zebra reconnects, members it no longer reports are dropped (ms). */
#define BFD_LAG_STALE_TIMEOUT 5000

/* A source address that disappears is given up only after this (ms). */
#define BFD_LAG_ADDR_CHECK 3000

/* Detection times below this are warned about (milliseconds). */
#define BFD_LAG_MIN_DETECT_WARN 150

enum bfd_lag_mode {
	BFD_LAG_MODE_STRICT = 0,
};

struct bfd_lag_member_stats {
	uint64_t rx_frames;	 /* frames read from the member socket */
	uint64_t rx_bad_frame;	 /* not a well-formed IP/UDP frame */
	uint64_t rx_mismatch;	 /* wrong addresses or port for this LAG */
	uint64_t rx_wrong_discr; /* Your Discriminator of another session */
	uint64_t rx_no_session;	 /* no session running on the member */
	uint64_t tx_frames;
	uint64_t tx_errors;
	uint64_t detach_count;
	uint64_t attach_count;
};

PREDECL_DLIST(bfd_lag_members);
struct bfd_lag;

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

	/* IPv4 micro-BFD session. */
	struct bfd_session *bs4;
	int port_sock; /* keeps the session's UDP source port reserved */
	uint16_t sport;
	struct event *t_read;

	/* Strict mode. */
	bool in_grace;
	struct event *t_grace;
	bool holdup_done;
	struct event *t_holdup;
	bool settling;
	struct event *t_settle;
	bool req_outstanding;
	bool req_attach;
	struct event *t_req;
	bool peer_admin_down;
	const char *reason;
	struct timeval last_action;

	struct bfd_lag_member_stats stats;
};
DECLARE_DLIST(bfd_lag_members, struct bfd_lag_member, item);

PREDECL_DLIST(bfd_lags);
struct bfd_lag {
	struct bfd_lags_item item;

	/* Configuration. */
	char name[IFNAMSIZ]; /* bond interface name */
	bool use_ipv4;
	bool has_dest4;
	struct in_addr dest4;
	bool has_src4;
	struct in_addr src4;
	bool admin_down;
	char *profile_name;
	enum bfd_lag_mode mode;
	uint32_t enable_grace; /* ms */
	uint32_t hold_up;      /* ms */

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

	/* IPv4 source address in use (INADDR_ANY: none). */
	struct in_addr local4;

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
void bfd_lag_set_use_ipv4(struct bfd_lag *lag, bool use);
void bfd_lag_set_ipv4_dest(struct bfd_lag *lag, const struct in_addr *addr);
void bfd_lag_set_ipv4_source(struct bfd_lag *lag, const struct in_addr *addr);
void bfd_lag_set_admin_down(struct bfd_lag *lag, bool admin_down);
void bfd_lag_set_profile(struct bfd_lag *lag, const char *profile);
void bfd_lag_set_mode(struct bfd_lag *lag, enum bfd_lag_mode mode);
void bfd_lag_set_enable_grace(struct bfd_lag *lag, uint32_t ms);
void bfd_lag_set_hold_up(struct bfd_lag *lag, uint32_t ms);
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
const struct bfd_session *bfd_lag_session_next(const struct bfd_lag *lag,
					       const struct bfd_session *bs);
const struct bfd_session *bfd_lag_session_find(const struct bfd_lag *lag, const char *ifname);
bool bfd_lag_session_detached(const struct bfd_session *bs);
bool bfd_lag_session_distributing(const struct bfd_session *bs);
const char *bfd_lag_session_reason(const struct bfd_session *bs);
void bfd_lag_session_counts(uint32_t *total, uint32_t *up, uint32_t *down, uint32_t *admin_down);

/* Show. */
void bfd_lag_show(struct vty *vty, const char *name, bool use_json);
void bfd_lag_show_statistics(struct vty *vty, bool use_json);
void bfd_lag_vrf_disable(struct bfd_vrf_global *bvrf);

const char *bfd_lag_mode2str(enum bfd_lag_mode mode);

#ifdef __cplusplus
}
#endif

#endif /* _BFD_LAG_H_ */
