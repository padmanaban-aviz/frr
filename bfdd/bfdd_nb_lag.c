// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon northbound: RFC 7130 micro-BFD (/frr-bfdd:bfdd/bfd/lag).
 *
 * Copyright (C) 2026 Aviz Networks
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"

#include "bfd.h"
#include "bfd_lag.h"
#include "bfdd_nb.h"

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session
 */
int bfdd_bfd_lag_session_create(struct nb_cb_create_args *args)
{
	struct bfd_lag *lag;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	lag = bfd_lag_new(yang_dnode_get_string(args->dnode, "lag-name"));
	nb_running_set_entry(args->dnode, lag);

	return NB_OK;
}

int bfdd_bfd_lag_session_destroy(struct nb_cb_destroy_args *args)
{
	struct bfd_lag *lag;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	lag = nb_running_unset_entry(args->dnode);
	bfd_lag_free(lag);

	return NB_OK;
}

void bfdd_bfd_lag_session_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bfd_lag *lag = nb_running_get_entry(args->dnode, NULL, true);

	bfd_lag_apply(lag);
}

static struct bfd_lag *lag_entry(const struct lyd_node *dnode)
{
	return nb_running_get_entry(dnode, NULL, true);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/use-ipv4
 */
int bfdd_bfd_lag_session_use_ipv4_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_use(lag_entry(args->dnode), BFD_LAG_AF_IPV4,
			yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/ipv4-dest-addr
 */
int bfdd_bfd_lag_session_ipv4_dest_addr_modify(struct nb_cb_modify_args *args)
{
	union bfd_lag_addr addr = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&addr.v4, args->dnode, NULL);
	bfd_lag_set_dest(lag_entry(args->dnode), BFD_LAG_AF_IPV4, &addr);
	return NB_OK;
}

int bfdd_bfd_lag_session_ipv4_dest_addr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_dest(lag_entry(args->dnode), BFD_LAG_AF_IPV4, NULL);
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/ipv4-source-addr
 */
int bfdd_bfd_lag_session_ipv4_source_addr_modify(struct nb_cb_modify_args *args)
{
	union bfd_lag_addr addr = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&addr.v4, args->dnode, NULL);
	bfd_lag_set_source(lag_entry(args->dnode), BFD_LAG_AF_IPV4, &addr);
	return NB_OK;
}

int bfdd_bfd_lag_session_ipv4_source_addr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_source(lag_entry(args->dnode), BFD_LAG_AF_IPV4, NULL);
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/use-ipv6
 */
int bfdd_bfd_lag_session_use_ipv6_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_use(lag_entry(args->dnode), BFD_LAG_AF_IPV6,
			yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/ipv6-dest-addr
 */
int bfdd_bfd_lag_session_ipv6_dest_addr_modify(struct nb_cb_modify_args *args)
{
	union bfd_lag_addr addr = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6(&addr.v6, args->dnode, NULL);
	bfd_lag_set_dest(lag_entry(args->dnode), BFD_LAG_AF_IPV6, &addr);
	return NB_OK;
}

int bfdd_bfd_lag_session_ipv6_dest_addr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_dest(lag_entry(args->dnode), BFD_LAG_AF_IPV6, NULL);
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/ipv6-source-addr
 */
int bfdd_bfd_lag_session_ipv6_source_addr_modify(struct nb_cb_modify_args *args)
{
	union bfd_lag_addr addr = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6(&addr.v6, args->dnode, NULL);
	bfd_lag_set_source(lag_entry(args->dnode), BFD_LAG_AF_IPV6, &addr);
	return NB_OK;
}

int bfdd_bfd_lag_session_ipv6_source_addr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_source(lag_entry(args->dnode), BFD_LAG_AF_IPV6, NULL);
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/admin-down
 */
int bfdd_bfd_lag_session_admin_down_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_admin_down(lag_entry(args->dnode), yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/profile
 */
int bfdd_bfd_lag_session_profile_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_profile(lag_entry(args->dnode), yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bfdd_bfd_lag_session_profile_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_profile(lag_entry(args->dnode), NULL);
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/mode
 */
int bfdd_bfd_lag_session_mode_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_mode(lag_entry(args->dnode), yang_dnode_get_enum(args->dnode, NULL));
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/enable-grace
 */
int bfdd_bfd_lag_session_enable_grace_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_enable_grace(lag_entry(args->dnode), yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/hold-up
 */
int bfdd_bfd_lag_session_hold_up_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_hold_up(lag_entry(args->dnode), yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

/*
 * Operational state.
 *
 * XPath: /frr-bfdd:bfdd/bfd/lag/session
 */
const void *bfdd_bfd_lag_session_get_next(struct nb_cb_get_next_args *args)
{
	return bfd_lag_next(args->list_entry);
}

int bfdd_bfd_lag_session_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct bfd_lag *lag = args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], lag->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

const void *bfdd_bfd_lag_session_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return bfd_lag_find(args->keys->key[0]);
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/member-links
 *
 * The list entry is the member. The session state leaves under
 * micro-bfd-ipv4 / micro-bfd-ipv6 call the callbacks of the other session
 * lists with the member's session of that family.
 */
const void *bfdd_bfd_lag_session_member_links_get_next(struct nb_cb_get_next_args *args)
{
	return bfd_lag_member_next(args->parent_list_entry, args->list_entry);
}

int bfdd_bfd_lag_session_member_links_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct bfd_lag_member *m = args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], m->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

const void *bfdd_bfd_lag_session_member_links_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return bfd_lag_member_find(args->parent_list_entry, args->keys->key[0]);
}

struct yang_data *
bfdd_bfd_lag_session_member_links_member_link_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct bfd_lag_member *m = args->list_entry;

	return yang_data_new_string(args->xpath, m->name);
}

struct yang_data *
bfdd_bfd_lag_session_member_links_detached_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_bool(args->xpath, bfd_lag_member_detached(args->list_entry));
}

struct yang_data *
bfdd_bfd_lag_session_member_links_distributing_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_bool(args->xpath, bfd_lag_member_distributing(args->list_entry));
}

struct yang_data *bfdd_bfd_lag_session_member_links_reason_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct bfd_lag_member *m = args->list_entry;

	return m->reason ? yang_data_new_string(args->xpath, m->reason) : NULL;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4|6/<leaf>
 */
#define LAG_SESSION_LEAF(af, AF, leaf)                                                            \
	struct yang_data *bfdd_bfd_lag_mbr_##af##_##leaf##_get_elem(                              \
		struct nb_cb_get_elem_args *args)                                                 \
	{                                                                                         \
		struct nb_cb_get_elem_args sargs = *args;                                         \
                                                                                                  \
		sargs.list_entry = bfd_lag_member_session(args->list_entry, BFD_LAG_AF_##AF);     \
		if (!sargs.list_entry)                                                            \
			return NULL;                                                              \
		return bfdd_bfd_sessions_single_hop_stats_##leaf##_get_elem(&sargs);              \
	}

#define LAG_SESSION_LEAVES(af, AF)                                                                \
	LAG_SESSION_LEAF(af, AF, local_discriminator)                                             \
	LAG_SESSION_LEAF(af, AF, local_state)                                                     \
	LAG_SESSION_LEAF(af, AF, local_diagnostic)                                                \
	LAG_SESSION_LEAF(af, AF, local_multiplier)                                                \
	LAG_SESSION_LEAF(af, AF, remote_discriminator)                                            \
	LAG_SESSION_LEAF(af, AF, remote_state)                                                    \
	LAG_SESSION_LEAF(af, AF, remote_diagnostic)                                               \
	LAG_SESSION_LEAF(af, AF, remote_multiplier)                                               \
	LAG_SESSION_LEAF(af, AF, negotiated_transmission_interval)                                \
	LAG_SESSION_LEAF(af, AF, negotiated_receive_interval)                                     \
	LAG_SESSION_LEAF(af, AF, detection_mode)                                                  \
	LAG_SESSION_LEAF(af, AF, last_down_time)                                                  \
	LAG_SESSION_LEAF(af, AF, last_up_time)                                                    \
	LAG_SESSION_LEAF(af, AF, session_down_count)                                              \
	LAG_SESSION_LEAF(af, AF, session_up_count)                                                \
	LAG_SESSION_LEAF(af, AF, control_packet_input_count)                                      \
	LAG_SESSION_LEAF(af, AF, control_packet_input_count_bad)                                  \
	LAG_SESSION_LEAF(af, AF, control_packet_output_count)                                     \
	LAG_SESSION_LEAF(af, AF, negotiated_echo_transmission_interval)                           \
	LAG_SESSION_LEAF(af, AF, echo_packet_input_count)                                         \
	LAG_SESSION_LEAF(af, AF, echo_packet_output_count)

LAG_SESSION_LEAVES(ipv4, IPV4)
LAG_SESSION_LEAVES(ipv6, IPV6)

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv4|6-session-statistics/summary
 */
static struct yang_data *lag_summary(struct nb_cb_get_elem_args *args, enum bfd_lag_af af,
				     int which)
{
	uint32_t total, up, down, admin_down;

	bfd_lag_session_counts(af, &total, &up, &down, &admin_down);
	switch (which) {
	case 0:
		return yang_data_new_uint32(args->xpath, total);
	case 1:
		return yang_data_new_uint32(args->xpath, up);
	case 2:
		return yang_data_new_uint32(args->xpath, down);
	default:
		return yang_data_new_uint32(args->xpath, admin_down);
	}
}

struct yang_data *bfdd_bfd_lag_ipv4_stats_sessions_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV4, 0);
}

struct yang_data *bfdd_bfd_lag_ipv4_stats_sessions_up_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV4, 1);
}

struct yang_data *bfdd_bfd_lag_ipv4_stats_sessions_down_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV4, 2);
}

struct yang_data *
bfdd_bfd_lag_ipv4_stats_sessions_admin_down_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV4, 3);
}

struct yang_data *bfdd_bfd_lag_ipv6_stats_sessions_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV6, 0);
}

struct yang_data *bfdd_bfd_lag_ipv6_stats_sessions_up_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV6, 1);
}

struct yang_data *bfdd_bfd_lag_ipv6_stats_sessions_down_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV6, 2);
}

struct yang_data *
bfdd_bfd_lag_ipv6_stats_sessions_admin_down_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, BFD_LAG_AF_IPV6, 3);
}
