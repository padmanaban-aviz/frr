// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"

#include "bfdd_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_bfdd_info = {
	.name = "frr-bfdd",
	.nodes = {
		{
			.xpath = "/frr-bfdd:bfdd/bfd",
			.cbs = {
				.create = bfdd_bfd_create,
				.destroy = bfdd_bfd_destroy,
				.cli_show = bfd_cli_show_header,
				.cli_show_end = bfd_cli_show_header_end,
			}
		},
		{
                        .xpath = "/frr-bfdd:bfdd/bfd/profile",
                        .cbs = {
                                .create = bfdd_bfd_profile_create,
                                .destroy = bfdd_bfd_profile_destroy,
				.cli_show = bfd_cli_show_profile,
				.cli_show_end = bfd_cli_show_peer_end,
                        }
                },
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/detection-multiplier",
                        .cbs = {
                                .modify = bfdd_bfd_profile_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
                        }
                },
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/desired-transmission-interval",
                        .cbs = {
                                .modify = bfdd_bfd_profile_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
                        }
                },
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/required-receive-interval",
                        .cbs = {
                                .modify = bfdd_bfd_profile_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
                        }
                },
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/administrative-down",
                        .cbs = {
                                .modify = bfdd_bfd_profile_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
                        }
                },
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/passive-mode",
                        .cbs = {
                                .modify = bfdd_bfd_profile_passive_mode_modify,
				.cli_show = bfd_cli_show_passive,
                        }
                },
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/log-session-changes",
                        .cbs = {
                                .modify = bfdd_bfd_profile_log_session_changes_modify,
				.cli_show = bfd_cli_show_log_session_changes,
                        }
                },
		{
			.xpath = "/frr-bfdd:bfdd/bfd/profile/minimum-ttl",
			.cbs = {
				.modify = bfdd_bfd_profile_minimum_ttl_modify,
				.cli_show = bfd_cli_show_minimum_ttl,
			}
		},
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/echo-mode",
                        .cbs = {
                                .modify = bfdd_bfd_profile_echo_mode_modify,
				.cli_show = bfd_cli_show_echo,
                        }
                },
		{
			.xpath = "/frr-bfdd:bfdd/bfd/profile/demand-mode",
			.cbs = {
				.modify = bfdd_bfd_profile_demand_mode_modify,
				.cli_show = bfd_cli_show_demand,
			}
		},
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/desired-echo-transmission-interval",
                        .cbs = {
                                .modify = bfdd_bfd_profile_desired_echo_transmission_interval_modify,
				.cli_show = bfd_cli_show_desired_echo_transmission_interval,
                        }
                },
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/profile/required-echo-receive-interval",
                        .cbs = {
                                .modify = bfdd_bfd_profile_required_echo_receive_interval_modify,
				.cli_show = bfd_cli_show_required_echo_receive_interval,
                        }
                },
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop",
			.cbs = {
				.create = bfdd_bfd_sessions_single_hop_create,
				.destroy = bfdd_bfd_sessions_single_hop_destroy,
				.get_next = bfdd_bfd_sessions_single_hop_get_next,
				.get_keys = bfdd_bfd_sessions_single_hop_get_keys,
				.lookup_entry = bfdd_bfd_sessions_single_hop_lookup_entry,
				.cli_show = bfd_cli_show_single_hop_peer,
				.cli_show_end = bfd_cli_show_peer_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/source-addr",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_source_addr_modify,
				.destroy = bfdd_bfd_sessions_single_hop_source_addr_destroy,
			}
		},
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/profile",
                        .cbs = {
                                .modify = bfdd_bfd_sessions_single_hop_profile_modify,
                                .destroy = bfdd_bfd_sessions_single_hop_profile_destroy,
				.cli_show = bfd_cli_peer_profile_show,
                        }
                },
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/passive-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_passive_mode_modify,
				.cli_show = bfd_cli_show_passive,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/log-session-changes",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_log_session_changes_modify,
				.cli_show = bfd_cli_show_log_session_changes,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/echo-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_echo_mode_modify,
				.cli_show = bfd_cli_show_echo,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/demand-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_demand_mode_modify,
				.cli_show = bfd_cli_show_demand,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/demand-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_multi_hop_demand_mode_modify,
				.cli_show = bfd_cli_show_demand,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/desired-echo-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify,
				.cli_show = bfd_cli_show_desired_echo_transmission_interval,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/required-echo-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_echo_receive_interval_modify,
				.cli_show = bfd_cli_show_required_echo_receive_interval,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-input-count-bad",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_bad_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop",
			.cbs = {
				.create = bfdd_bfd_sessions_multi_hop_create,
				.destroy = bfdd_bfd_sessions_multi_hop_destroy,
				.get_next = bfdd_bfd_sessions_multi_hop_get_next,
				.get_keys = bfdd_bfd_sessions_multi_hop_get_keys,
				.lookup_entry = bfdd_bfd_sessions_multi_hop_lookup_entry,
				.cli_show = bfd_cli_show_multi_hop_peer,
				.cli_show_end = bfd_cli_show_peer_end,
			}
		},
                {
                        .xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/profile",
                        .cbs = {
                                .modify = bfdd_bfd_sessions_single_hop_profile_modify,
                                .destroy = bfdd_bfd_sessions_single_hop_profile_destroy,
				.cli_show = bfd_cli_peer_profile_show,
                        }
                },
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/passive-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_passive_mode_modify,
				.cli_show = bfd_cli_show_passive,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/log-session-changes",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_log_session_changes_modify,
				.cli_show = bfd_cli_show_log_session_changes,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/minimum-ttl",
			.cbs = {
				.modify = bfdd_bfd_sessions_multi_hop_minimum_ttl_modify,
				.cli_show = bfd_cli_show_minimum_ttl,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/control-packet-input-count-bad",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_bad_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo",
			.cbs = {
				.create = bfdd_bfd_sessions_sbfd_echo_create,
				.destroy = bfdd_bfd_sessions_sbfd_echo_destroy,
				.get_next = bfdd_bfd_sessions_sbfd_echo_get_next,
				.get_keys = bfdd_bfd_sessions_sbfd_echo_get_keys,
				.lookup_entry = bfdd_bfd_sessions_sbfd_echo_lookup_entry,
				.cli_show = bfd_cli_show_sbfd_echo_peer, /* TODO */
				.cli_show_end = bfd_cli_show_peer_end, /* TODO */
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/dest-addr",
			.cbs = {
				.modify = bfdd_bfd_sessions_sbfd_echo_dest_addr_modify,
				.destroy = bfdd_bfd_sessions_sbfd_echo_dest_addr_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/srv6-source-ipv6",
			.cbs = {
				.modify = bfdd_bfd_sessions_sbfd_srv6_source_ipv6_modify,
				.destroy = bfdd_bfd_sessions_sbfd_srv6_source_ipv6_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/profile",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_profile_modify,
				.destroy = bfdd_bfd_sessions_single_hop_profile_destroy,
				.cli_show = bfd_cli_peer_profile_show,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/echo-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_sbfd_echo_mode_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/desired-echo-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_echo_transmission_interval_modify,
				.cli_show = bfd_cli_show_desired_echo_transmission_interval,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/required-echo-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_echo_receive_interval_modify,
				.cli_show = bfd_cli_show_required_echo_receive_interval,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/passive-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_passive_mode_modify,
				.cli_show = bfd_cli_show_passive,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/log-session-changes",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_log_session_changes_modify,
				.cli_show = bfd_cli_show_log_session_changes,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/bfd-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_bfd_mode_modify,
				.destroy = bfdd_bfd_sessions_bfd_mode_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/srv6-encap-data",
			.cbs = {
				.create = bfdd_bfd_sessions_segment_list_create,
				.destroy = bfdd_bfd_sessions_segment_list_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/minimum-ttl",
			.cbs = {
				.modify = bfdd_bfd_sessions_multi_hop_minimum_ttl_modify,
				.cli_show = bfd_cli_show_minimum_ttl,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/multi-hop",
			.cbs = {
				.modify = bfdd_bfd_sessions_sbfd_multi_hop_modify,
				.destroy = bfdd_bfd_sessions_sbfd_multi_hop_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/control-packet-input-count-bad",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_bad_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init",
			.cbs = {
				.create = bfdd_bfd_sessions_sbfd_init_create,
				.destroy = bfdd_bfd_sessions_sbfd_init_destroy,
				.get_next = bfdd_bfd_sessions_sbfd_init_get_next,
				.get_keys = bfdd_bfd_sessions_sbfd_init_get_keys,
				.lookup_entry = bfdd_bfd_sessions_sbfd_init_lookup_entry,
				.cli_show = bfd_cli_show_sbfd_init_peer, /* TODO */
				.cli_show_end = bfd_cli_show_peer_end, /* TODO */
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/srv6-source-ipv6",
			.cbs = {
				.modify = bfdd_bfd_sessions_sbfd_srv6_source_ipv6_modify,
				.destroy = bfdd_bfd_sessions_sbfd_srv6_source_ipv6_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/remote-discr",
			.cbs = {
				.modify = bfdd_bfd_sessions_sbfd_init_remote_discr_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/profile",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_profile_modify,
				.destroy = bfdd_bfd_sessions_single_hop_profile_destroy,
				.cli_show = bfd_cli_peer_profile_show,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/detection-multiplier",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_detection_multiplier_modify,
				.cli_show = bfd_cli_show_mult,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/desired-transmission-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_desired_transmission_interval_modify,
				.cli_show = bfd_cli_show_tx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/required-receive-interval",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_required_receive_interval_modify,
				.cli_show = bfd_cli_show_rx,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/administrative-down",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_administrative_down_modify,
				.cli_show = bfd_cli_show_shutdown,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/passive-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_passive_mode_modify,
				.cli_show = bfd_cli_show_passive,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/log-session-changes",
			.cbs = {
				.modify = bfdd_bfd_sessions_single_hop_log_session_changes_modify,
				.cli_show = bfd_cli_show_log_session_changes,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/bfd-mode",
			.cbs = {
				.modify = bfdd_bfd_sessions_bfd_mode_modify,
				.destroy = bfdd_bfd_sessions_bfd_mode_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/srv6-encap-data",
			.cbs = {
				.create = bfdd_bfd_sessions_segment_list_create,
				.destroy = bfdd_bfd_sessions_segment_list_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/minimum-ttl",
			.cbs = {
				.modify = bfdd_bfd_sessions_multi_hop_minimum_ttl_modify,
				.cli_show = bfd_cli_show_minimum_ttl,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/multi-hop",
			.cbs = {
				.modify = bfdd_bfd_sessions_sbfd_multi_hop_modify,
				.destroy = bfdd_bfd_sessions_sbfd_multi_hop_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/control-packet-input-count-bad",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_input_count_bad_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/stats/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_sessions_single_hop_stats_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/profile/profile-authentication/authentication-key-chain",
			.cbs = {
				.modify = bfdd_bfd_profile_authentication_key_chain_modify,
				.destroy = bfdd_bfd_profile_authentication_key_chain_destroy,
				.cli_show = bfd_cli_show_profile_authentication_key_chain,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/profile/profile-authentication/authentication-algorithm-meticulous",
			.cbs = {
				.modify = bfdd_bfd_profile_authentication_algorithm_meticulous_modify,
				.destroy = bfdd_bfd_profile_authentication_algorithm_meticulous_destroy,
				.cli_show = bfd_cli_show_profile_authentication_algorithm_meticulous,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/authentication-key-chain",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_key_chain_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_key_chain_destroy,
				.cli_show = bfd_cli_show_auth,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/single-hop/authentication-algorithm-meticulous",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_destroy,
				.cli_show = bfd_cli_show_auth_algorithm_meticulous,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/authentication-key-chain",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_key_chain_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_key_chain_destroy,
				.cli_show = bfd_cli_show_auth,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/multi-hop/authentication-algorithm-meticulous",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_destroy,
				.cli_show = bfd_cli_show_auth_algorithm_meticulous,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/authentication-key-chain",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_key_chain_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_key_chain_destroy,
				.cli_show = bfd_cli_show_auth,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-echo/authentication-algorithm-meticulous",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_destroy,
				.cli_show = bfd_cli_show_auth_algorithm_meticulous,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/authentication-key-chain",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_key_chain_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_key_chain_destroy,
				.cli_show = bfd_cli_show_auth,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/sessions/sbfd-init/authentication-algorithm-meticulous",
			.cbs = {
				.modify = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_modify,
				.destroy = bfdd_bfd_sessions_common_authentication_algorithm_meticulous_destroy,
				.cli_show = bfd_cli_show_auth_algorithm_meticulous,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session",
			.cbs = {
				.create = bfdd_bfd_lag_session_create,
				.destroy = bfdd_bfd_lag_session_destroy,
				.apply_finish = bfdd_bfd_lag_session_apply_finish,
				.get_next = bfdd_bfd_lag_session_get_next,
				.get_keys = bfdd_bfd_lag_session_get_keys,
				.lookup_entry = bfdd_bfd_lag_session_lookup_entry,
				.cli_show = bfd_cli_show_lag,
				.cli_show_end = bfd_cli_show_lag_end,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/use-ipv4",
			.cbs = {
				.modify = bfdd_bfd_lag_session_use_ipv4_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/ipv4-dest-addr",
			.cbs = {
				.modify = bfdd_bfd_lag_session_ipv4_dest_addr_modify,
				.destroy = bfdd_bfd_lag_session_ipv4_dest_addr_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/ipv4-source-addr",
			.cbs = {
				.modify = bfdd_bfd_lag_session_ipv4_source_addr_modify,
				.destroy = bfdd_bfd_lag_session_ipv4_source_addr_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/use-ipv6",
			.cbs = {
				.modify = bfdd_bfd_lag_session_use_ipv6_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/ipv6-dest-addr",
			.cbs = {
				.modify = bfdd_bfd_lag_session_ipv6_dest_addr_modify,
				.destroy = bfdd_bfd_lag_session_ipv6_dest_addr_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/ipv6-source-addr",
			.cbs = {
				.modify = bfdd_bfd_lag_session_ipv6_source_addr_modify,
				.destroy = bfdd_bfd_lag_session_ipv6_source_addr_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/admin-down",
			.cbs = {
				.modify = bfdd_bfd_lag_session_admin_down_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/profile",
			.cbs = {
				.modify = bfdd_bfd_lag_session_profile_modify,
				.destroy = bfdd_bfd_lag_session_profile_destroy,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/mode",
			.cbs = {
				.modify = bfdd_bfd_lag_session_mode_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/enable-grace",
			.cbs = {
				.modify = bfdd_bfd_lag_session_enable_grace_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/hold-up",
			.cbs = {
				.modify = bfdd_bfd_lag_session_hold_up_modify,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links",
			.cbs = {
				.get_next = bfdd_bfd_lag_session_member_links_get_next,
				.get_keys = bfdd_bfd_lag_session_member_links_get_keys,
				.lookup_entry = bfdd_bfd_lag_session_member_links_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/member-link",
			.cbs = {
				.get_elem = bfdd_bfd_lag_session_member_links_member_link_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/detached",
			.cbs = {
				.get_elem = bfdd_bfd_lag_session_member_links_detached_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/distributing",
			.cbs = {
				.get_elem = bfdd_bfd_lag_session_member_links_distributing_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/reason",
			.cbs = {
				.get_elem = bfdd_bfd_lag_session_member_links_reason_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/control-packet-input-count-bad",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_control_packet_input_count_bad_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv4/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv4_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/local-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_local_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/local-state",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_local_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/local-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_local_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/local-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_local_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/remote-discriminator",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_remote_discriminator_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/remote-state",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_remote_state_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/remote-diagnostic",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_remote_diagnostic_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/remote-multiplier",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_remote_multiplier_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/negotiated-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_negotiated_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/negotiated-receive-interval",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_negotiated_receive_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/detection-mode",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_detection_mode_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/last-down-time",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_last_down_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/last-up-time",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_last_up_time_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/session-down-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_session_down_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/session-up-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_session_up_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/control-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_control_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/control-packet-input-count-bad",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_control_packet_input_count_bad_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/control-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_control_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/negotiated-echo-transmission-interval",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_negotiated_echo_transmission_interval_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/echo-packet-input-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_echo_packet_input_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/session/member-links/micro-bfd-ipv6/echo-packet-output-count",
			.cbs = {
				.get_elem = bfdd_bfd_lag_mbr_ipv6_echo_packet_output_count_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv4-session-statistics/summary/number-of-sessions",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv4_stats_sessions_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv4-session-statistics/summary/number-of-sessions-up",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv4_stats_sessions_up_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv4-session-statistics/summary/number-of-sessions-down",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv4_stats_sessions_down_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv4-session-statistics/summary/number-of-sessions-admin-down",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv4_stats_sessions_admin_down_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv6-session-statistics/summary/number-of-sessions",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv6_stats_sessions_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv6-session-statistics/summary/number-of-sessions-up",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv6_stats_sessions_up_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv6-session-statistics/summary/number-of-sessions-down",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv6_stats_sessions_down_get_elem,
			}
		},
		{
			.xpath = "/frr-bfdd:bfdd/bfd/lag/micro-bfd-ipv6-session-statistics/summary/number-of-sessions-admin-down",
			.cbs = {
				.get_elem = bfdd_bfd_lag_ipv6_stats_sessions_admin_down_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
