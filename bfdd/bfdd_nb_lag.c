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

	bfd_lag_set_use_ipv4(lag_entry(args->dnode), yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/ipv4-dest-addr
 */
int bfdd_bfd_lag_session_ipv4_dest_addr_modify(struct nb_cb_modify_args *args)
{
	struct in_addr addr;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&addr, args->dnode, NULL);
	bfd_lag_set_ipv4_dest(lag_entry(args->dnode), &addr);
	return NB_OK;
}

int bfdd_bfd_lag_session_ipv4_dest_addr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_ipv4_dest(lag_entry(args->dnode), NULL);
	return NB_OK;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/session/ipv4-source-addr
 */
int bfdd_bfd_lag_session_ipv4_source_addr_modify(struct nb_cb_modify_args *args)
{
	struct in_addr addr;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4(&addr, args->dnode, NULL);
	bfd_lag_set_ipv4_source(lag_entry(args->dnode), &addr);
	return NB_OK;
}

int bfdd_bfd_lag_session_ipv4_source_addr_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bfd_lag_set_ipv4_source(lag_entry(args->dnode), NULL);
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
 * The list entry is the member's micro-BFD session, so the session state
 * leaves under micro-bfd-ipv4 share the callbacks of the other session
 * lists.
 */
const void *bfdd_bfd_lag_session_member_links_get_next(struct nb_cb_get_next_args *args)
{
	return bfd_lag_session_next(args->parent_list_entry, args->list_entry);
}

int bfdd_bfd_lag_session_member_links_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], bs->key.ifname, sizeof(args->keys->key[0]));
	return NB_OK;
}

const void *bfdd_bfd_lag_session_member_links_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return bfd_lag_session_find(args->parent_list_entry, args->keys->key[0]);
}

struct yang_data *
bfdd_bfd_lag_session_member_links_member_link_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct bfd_session *bs = args->list_entry;

	return yang_data_new_string(args->xpath, bs->key.ifname);
}

struct yang_data *
bfdd_bfd_lag_session_member_links_detached_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_bool(args->xpath, bfd_lag_session_detached(args->list_entry));
}

struct yang_data *
bfdd_bfd_lag_session_member_links_distributing_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_bool(args->xpath, bfd_lag_session_distributing(args->list_entry));
}

struct yang_data *bfdd_bfd_lag_session_member_links_reason_get_elem(struct nb_cb_get_elem_args *args)
{
	const char *reason = bfd_lag_session_reason(args->list_entry);

	return reason ? yang_data_new_string(args->xpath, reason) : NULL;
}

/*
 * XPath: /frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv4-session-statistics/summary
 */
static struct yang_data *lag_summary(struct nb_cb_get_elem_args *args, int which)
{
	uint32_t total, up, down, admin_down;

	bfd_lag_session_counts(&total, &up, &down, &admin_down);
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

struct yang_data *bfdd_bfd_lag_stats_sessions_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, 0);
}

struct yang_data *bfdd_bfd_lag_stats_sessions_up_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, 1);
}

struct yang_data *bfdd_bfd_lag_stats_sessions_down_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, 2);
}

struct yang_data *bfdd_bfd_lag_stats_sessions_admin_down_get_elem(struct nb_cb_get_elem_args *args)
{
	return lag_summary(args, 3);
}
