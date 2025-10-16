/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

#include "pfcp_ie.h"


/*
 *	PFCP PFD Management Grouped IEs
 */
struct pfcp_ie_pfd_context {
	/* Optional IEs */
	struct pfcp_ie_pfd_contents *pfd_contents;
};

struct pfcp_ie_application_id_pfds {
	/* Mandatory IEs */
	struct pfcp_ie_application_id *application_id;
	/* Optional IEs */
	struct pfcp_ie_pfd_context *pfd_context;
};


/*
 *	PFCP Association Setup Grouped IEs
 */
struct pfcp_ie_session_retention_information {
	struct pfcp_ie_cp_pfcp_entity_ip_address *cp_pfcp_entity_ip_address;
};

struct pfcp_ie_ue_ip_address_pool_information {
	struct pfcp_ie_ue_ip_address_pool_identity *ue_ip_address_pool_identity;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_s_nssai *s_nssai;
	struct pfcp_ie_ip_version *ip_version;
};


/*
 *	PFCP Association Update Grouped IEs
 */
struct pfcp_ie_gtp_u_path_qos_control_information {
	/* Mandatory IEs */
	struct pfcp_ie_remote_gtp_u_peer *remote_gtp_u_peer;
	/* Optional IEs */
	struct pfcp_ie_gtp_u_path_interface_type *gtp_u_path_interface_type;
	struct pfcp_ie_qos_report_trigger *qos_report_trigger;
	struct pfcp_ie_transport_level_marking *transport_level_marking;
	struct pfcp_ie_measurement_period *measurement_period;
	struct pfcp_ie_mt_edt_control_information *mt_edt_control_information;
};

struct pfcp_ie_gtp_u_path_qos_report {
	/* Mandatory IEs */
	struct pfcp_ie_remote_gtp_u_peer *remote_gtp_u_peer;
	/* Optional IEs */
	struct pfcp_ie_gtp_u_path_interface_type *gtp_u_path_interface_type;
	struct pfcp_ie_qos_report_trigger *qos_report_trigger;
	struct pfcp_ie_time_stamp *start_time;
	struct pfcp_ie_measurement_period *measurement_period;
	struct pfcp_ie_minimum_wait_time *minimum_wait_time;
};

struct pfcp_ie_ue_ip_address_usage_information {
	/* Mandatory IEs */
	struct pfcp_ie_sequence_number *sequence_number;
	struct pfcp_ie_metric *number_of_ue_ip_addresses;
	struct pfcp_ie_validity_timer *validity_timer;
	struct pfcp_ie_number_of_ue_ip_addresses *number_of_ue_ip_addresses_ie;
	/* Optional IEs */
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_ue_ip_address_pool_identity *ue_ip_address_pool_identity;
	struct pfcp_ie_s_nssai *s_nssai;
};


/*
 *	PFCP Node Report Grouped IEs
 */
struct pfcp_ie_user_plane_path_failure_report {
	/* Mandatory IEs */
	struct pfcp_ie_remote_gtp_u_peer *remote_gtp_u_peer;
};

struct pfcp_ie_user_plane_path_recovery_report {
	/* Mandatory IEs */
	struct pfcp_ie_remote_gtp_u_peer *remote_gtp_u_peer;
};

struct pfcp_ie_peer_up_restart_report {
	/* Mandatory IEs */
	struct pfcp_ie_remote_gtp_u_peer *remote_gtp_u_peer;
};


/*
 *	PFCP Session Set Modification Grouped IEs
 */
struct pfcp_ie_session_change_info {
	/* Mandatory IEs */
	struct pfcp_ie_alternative_smf_ip_address *alternative_smf_pgwc_ip_address;
	/* Conditional IEs */
	struct pfcp_ie_fq_csid *pgwc_smf_fq_csid;
	struct pfcp_ie_group_id *groupe_id;
	struct pfcp_ie_cp_ip_address *cp_ip_address;
};


/*
 *	PFCP Session Establishment Request Grouped IEs
 */

/* Redundant Transmission Detection Parameters IE */
struct pfcp_ie_redundant_transmission_detection_parameters {
	/* Optional IEs */
	struct pfcp_ie_f_teid *f_teid;
	struct pfcp_ie_network_instance *network_instance;
};

/* Ethernet Packet Filter Grouped IE */
struct pfcp_ie_ethernet_packet_filter {
	/* Optional IEs */
	struct pfcp_ie_ethernet_filter_id *ethernet_filter_id;
	struct pfcp_ie_ethernet_filter_properties *ethernet_filter_properties;
	struct pfcp_ie_mac_address *mac_address;
	struct pfcp_ie_ethertype *ethertype;
	struct pfcp_ie_c_tag *c_tag;
	struct pfcp_ie_s_tag *s_tag;
	struct pfcp_ie_sdf_filter *sdf_filter;
};

/* PDI (Packet Detection Information) Grouped IE */
struct pfcp_ie_pdi {
	/* Mandatory IEs */
	struct pfcp_ie_source_interface *source_interface;
	/* Optional IEs */
	struct pfcp_ie_f_teid *local_f_teid;
	struct pfcp_ie_local_ingress_tunnel *local_ingress_tunnel;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_redundant_transmission_detection_parameters *redundant_transmission_detection_parameters;
	struct pfcp_ie_ue_ip_address *ue_ip_address;
	struct pfcp_ie_traffic_endpoint_id *traffic_endpoint_id;
	struct pfcp_ie_sdf_filter *sdf_filter;
	struct pfcp_ie_application_id *application_id;
	struct pfcp_ie_ethernet_pdu_session_information *ethernet_pdu_session_information;
	struct pfcp_ie_ethernet_packet_filter *ethernet_packet_filter;
	struct pfcp_ie_qfi *qfi;
	struct pfcp_ie_framed_route *framed_route;
	struct pfcp_ie_framed_routing *framed_routing;
	struct pfcp_ie_framed_ipv6_route *framed_ipv6_route;
	struct pfcp_ie_3gpp_interface_type *source_interface_type;
	struct pfcp_ie_area_session_id *area_session_id;
};

/* Create PDR (Packet Detection Rule) Grouped IE */
struct pfcp_ie_create_pdr {
	/* Mandatory IEs */
	struct pfcp_ie_pdr_id *pdr_id;
	struct pfcp_ie_precedence *precedence;
	struct pfcp_ie_pdi *pdi;
	/* Optional IEs */
	struct pfcp_ie_outer_header_removal *outer_header_removal;
	struct pfcp_ie_far_id *far_id;
	struct pfcp_ie_urr_id *urr_id;
	struct pfcp_ie_qer_id *qer_id;
	struct pfcp_ie_mar_id *mar_id;
	struct pfcp_ie_activate_predefined_rules *activate_predefined_rules;
	struct pfcp_ie_activation_time *activation_time;
	struct pfcp_ie_deactivation_time *deactivation_time;
	struct pfcp_ie_ue_ip_address_pool_identity *ue_ip_address_pool_identity;
	struct pfcp_ie_rat_type *rat_type;
};

/* Create FAR (Forwarding Action Rule) Grouped IE */
struct pfcp_ie_forwarding_parameters {
	/* Optional IEs */
	struct pfcp_ie_destination_interface *destination_interface;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_redirect_information *redirect_information;
	struct pfcp_ie_outer_header_creation *outer_header_creation;
	struct pfcp_ie_transport_level_marking *transport_level_marking;
	struct pfcp_ie_forwarding_policy *forwarding_policy;
	struct pfcp_ie_header_enrichment *header_enrichment;
	struct pfcp_ie_traffic_endpoint_id *linked_traffic_endpoint_id;
	struct pfcp_ie_proxying *proxying;
	struct pfcp_ie_3gpp_interface_type *destination_interface_type;
	struct pfcp_ie_data_network_access_identifier *data_network_access_identifier;
	struct pfcp_ie_ip_address_and_port_number_replacement *ip_address_and_port_number_replacement;
};
struct pfcp_ie_duplicating_parameters {
	/* Optional IEs */
	struct pfcp_ie_destination_interface *destination_interface;
	struct pfcp_ie_outer_header_creation *outer_header_creation;
	struct pfcp_ie_transport_level_marking *transport_level_marking;
	struct pfcp_ie_forwarding_policy *forwarding_policy;
};
struct pfcp_ie_create_far {
	/* Mandatory IEs */
	struct pfcp_ie_far_id *far_id;
	struct pfcp_ie_apply_action *apply_action;
	/* Optional IEs */
	struct pfcp_ie_forwarding_parameters *forwarding_parameters;
	struct pfcp_ie_duplicating_parameters *duplicating_parameters;
	struct pfcp_ie_bar_id *bar_id;
};

/* Create URR (Usage Reporting Rule) Grouped IE */
struct pfcp_ie_aggregated_urrs {
	/* Mandatory IEs */
	struct pfcp_ie_aggregated_urr_id *aggregated_urr_id;
	/* Optional IEs */
	struct pfcp_ie_multiplier *multiplier;
};
struct pfcp_ie_additional_monitoring_time {
	/* Mandatory IEs */
	struct pfcp_ie_monitoring_time *monitoring_time;
	/* Optional IEs */
	struct pfcp_ie_subsequent_volume_threshold *subsequent_volume_threshold;
	struct pfcp_ie_subsequent_time_threshold *subsequent_time_threshold;
	struct pfcp_ie_subsequent_volume_quota *subsequent_volume_quota;
	struct pfcp_ie_subsequent_time_quota *subsequent_time_quota;
	struct pfcp_ie_subsequent_event_threshold *subsequent_event_threshold;
	struct pfcp_ie_subsequent_event_quota *subsequent_event_quota;
	struct pfcp_ie_event_threshold *event_threshold;
	struct pfcp_ie_event_quota *event_quota;
};
struct pfcp_ie_create_urr {
	/* Mandatory IEs */
	struct pfcp_ie_urr_id *urr_id;
	struct pfcp_ie_measurement_method *measurement_method;
	struct pfcp_ie_reporting_triggers *reporting_triggers;
	/* Optional IEs */
	struct pfcp_ie_measurement_period *measurement_period;
	struct pfcp_ie_volume_threshold *volume_threshold;
	struct pfcp_ie_volume_quota *volume_quota;
	struct pfcp_ie_event_threshold *event_threshold;
	struct pfcp_ie_event_quota *event_quota;
	struct pfcp_ie_time_threshold *time_threshold;
	struct pfcp_ie_time_quota *time_quota;
	struct pfcp_ie_quota_holding_time *quota_holding_time;
	struct pfcp_ie_dropped_dl_traffic_threshold *dropped_dl_traffic_threshold;
	struct pfcp_ie_quota_validity_time *quota_validity_time;
	struct pfcp_ie_monitoring_time *monitoring_time;
	struct pfcp_ie_subsequent_volume_threshold *subsequent_volume_threshold;
	struct pfcp_ie_subsequent_time_threshold *subsequent_time_threshold;
	struct pfcp_ie_subsequent_volume_quota *subsequent_volume_quota;
	struct pfcp_ie_subsequent_time_quota *subsequent_time_quota;
	struct pfcp_ie_subsequent_event_threshold *subsequent_event_threshold;
	struct pfcp_ie_subsequent_event_quota *subsequent_event_quota;
	struct pfcp_ie_inactivity_detection_time *inactivity_detection_time;
	struct pfcp_ie_linked_urr_id *linked_urr_id;
	struct pfcp_ie_measurement_information *measurement_information;
	struct pfcp_ie_time_quota_mechanism *time_quota_mechanism;
	struct pfcp_ie_aggregated_urrs *aggregated_urrs;
	struct pfcp_ie_far_id *far_id_for_quota_action;
	struct pfcp_ie_ethernet_inactivity_timer *ethernet_inactivity_timer;
	struct pfcp_ie_additional_monitoring_time *additional_monitoring_time;
	struct pfcp_ie_number_of_reports *number_of_reports;
};

/* Create QER (QoS Enhancement Rule) Grouped IE */
struct pfcp_ie_create_qer {
	/* Mandatory IEs */
	struct pfcp_ie_qer_id *qer_id;
	struct pfcp_ie_qer_correlation_id *qer_correlation_id;
	struct pfcp_ie_gate_status *gate_status;
	/* Optional IEs */
	struct pfcp_ie_mbr *maximum_bitrate;
	struct pfcp_ie_gbr *guaranteed_bitrate;
	struct pfcp_ie_packet_rate *packet_rate;
	struct pfcp_ie_packet_rate_status *packet_rate_status;
	struct pfcp_ie_dl_flow_level_marking *dl_flow_level_marking;
	struct pfcp_ie_qfi *qos_flow_identifier;
	struct pfcp_ie_rqi *reflective_qos;
	struct pfcp_ie_paging_policy_indicator *paging_policy_indicator;
	struct pfcp_ie_averaging_window *averaging_window;
	struct pfcp_ie_qer_control_indications *qer_control_indications;
	struct pfcp_ie_qer_indications *qer_indications;
};

/* Create BAR (Buffering Action Rule) Grouped IE */
struct pfcp_ie_create_bar {
	/* Mandatory IEs */
	struct pfcp_ie_bar_id *bar_id;
	/* Optional IEs */
	struct pfcp_ie_downlink_data_notification_delay *downlink_data_notification_delay;
	struct pfcp_ie_suggested_buffering_packets_count *suggested_buffering_packets_count;
	struct pfcp_ie_mt_edt_control_information *mt_edt_control_information;
	struct pfcp_ie_dl_buffering_duration *dl_buffering_duration;
	struct pfcp_ie_dl_buffering_suggested_packet_count *dl_buffering_suggested_packet_count;
};

/* Create Traffic Endpoint Grouped IE */
struct pfcp_ie_create_traffic_endpoint {
	/* Mandatory IEs */
	struct pfcp_ie_traffic_endpoint_id *traffic_endpoint_id;
	/* Optional IEs */
	struct pfcp_ie_f_teid *local_f_teid;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_redundant_transmission_detection_parameters *redundant_transmission_detection_parameters;
	struct pfcp_ie_ue_ip_address *ue_ip_address;
	struct pfcp_ie_ethernet_pdu_session_information *ethernet_pdu_session_information;
	struct pfcp_ie_framed_route *framed_route;
	struct pfcp_ie_framed_routing *framed_routing;
	struct pfcp_ie_framed_ipv6_route *framed_ipv6_route;
	struct pfcp_ie_qfi *qfi;
	struct pfcp_ie_3gpp_interface_type *source_interface_type;
	struct pfcp_ie_local_ingress_tunnel *local_ingress_tunnel;
	struct pfcp_ie_area_session_id *area_session_id;
	struct pfcp_ie_rat_type *rat_type;
};

/* Create MAR (Multicast Access Rule) Grouped IE */
struct pfcp_ie_create_mar {
	/* Mandatory IEs */
	struct pfcp_ie_mar_id *mar_id;
	struct pfcp_ie_steering_functionality *steering_functionality;
	struct pfcp_ie_steering_mode *steering_mode;
	/* FIXME: ...Just Basic support for now...*/
};

/* Create SRR (Session Report Rule) Grouped IE */
struct pfcp_ie_create_srr {
	/* Mandatory IEs */
	struct pfcp_ie_srr_id *srr_id;
	/* FIXME: ...Just Basic support for now...*/
};


/*
 *	PFCP Session Establishment Response Grouped IEs
 */

/* Created PDR Grouped IE */
struct pfcp_ie_created_pdr {
	/* Mandatory IEs */
	struct pfcp_ie_pdr_id *pdr_id;
	/* Optional IEs */
	struct pfcp_ie_f_teid *local_f_teid;
	struct pfcp_ie_ue_ip_address *ue_ip_address;
};

/* Load Control Information Grouped IE */
struct pfcp_ie_load_control_information {
	/* Mandatory IEs */
	struct pfcp_ie_sequence_number *load_control_sequence_number;
	struct pfcp_ie_metric *load_metric;
};

/* Overload Control Information Grouped IE */
struct pfcp_ie_overload_control_information {
	/* Mandatory IEs */
	struct pfcp_ie_sequence_number *overload_control_sequence_number;
	struct pfcp_ie_metric *overload_reduction_metric;
	struct pfcp_ie_timer *period_of_validity;
	/* Optional IEs */
	struct pfcp_ie_oci_flags *overload_control_information_flags;
};

/* Created Traffic Endpoint Grouped IE */
struct pfcp_ie_created_traffic_endpoint {
	/* Mandatory IEs */
	struct pfcp_ie_traffic_endpoint_id *traffic_endpoint_id;
	struct pfcp_ie_local_ingress_tunnel *local_ingress_tunnel;
	/* Optional IEs */
	struct pfcp_ie_f_teid *local_f_teid;
	struct pfcp_ie_ue_ip_address *ue_ip_address;
};

/* Partial Failure Grouped IE */
struct pfcp_ie_partial_failure_information {
	/* Mandatory IEs */
	struct pfcp_ie_failed_rule_id *failed_rule_id;
	struct pfcp_ie_cause *cause;
	struct pfcp_ie_offending_ie_information *offending_ie_information;
};


/*
 *	PFCP Session Modification Request Grouped IEs
 */

/* Remove PDR Grouped IE */
struct pfcp_ie_remove_pdr {
	/* Mandatory IEs */
	struct pfcp_ie_pdr_id *pdr_id;
};

/* Remove FAR Grouped IE */
struct pfcp_ie_remove_far {
	/* Mandatory IEs */
	struct pfcp_ie_far_id *far_id;
};

/* Remove URR Grouped IE */
struct pfcp_ie_remove_urr {
	/* Mandatory IEs */
	struct pfcp_ie_urr_id *urr_id;
};

/* Remove QER Grouped IE */
struct pfcp_ie_remove_qer {
	/* Mandatory IEs */
	struct pfcp_ie_qer_id *qer_id;
};

/* Remove BAR Grouped IE */
struct pfcp_ie_remove_bar {
	/* Mandatory IEs */
	struct pfcp_ie_bar_id *bar_id;
};

/* Remove Traffic Endpoint Grouped IE */
struct pfcp_ie_remove_traffic_endpoint {
	/* Mandatory IEs */
	struct pfcp_ie_traffic_endpoint_id *traffic_endpoint_id;
};

/* Remove MAR Grouped IE */
struct pfcp_ie_remove_mar {
	/* Mandatory IEs */
	struct pfcp_ie_mar_id *mar_id;
};

/* Remove SRR Grouped IE */
struct pfcp_ie_remove_srr {
	/* Mandatory IEs */
	struct pfcp_ie_srr_id *srr_id;
};

/* Update PDR Grouped IE */
struct pfcp_ie_update_pdr {
	/* Mandatory IEs */
	struct pfcp_ie_pdr_id *pdr_id;
	/* Optional IEs */
	struct pfcp_ie_outer_header_removal *outer_header_removal;
	struct pfcp_ie_precedence *precedence;
	struct pfcp_ie_pdi *pdi;
	struct pfcp_ie_far_id *far_id;
	struct pfcp_ie_urr_id *urr_id;
	struct pfcp_ie_qer_id *qer_id;
	struct pfcp_ie_activate_predefined_rules *activate_predefined_rules;
	struct pfcp_ie_deactivate_predefined_rules *deactivate_predefined_rules;
	struct pfcp_ie_activation_time *activation_time;
	struct pfcp_ie_deactivation_time *deactivation_time;
};

/* Update Forwarding Parameters Grouped IE */
struct pfcp_ie_update_forwarding_parameters {
	/* Optional IEs */
	struct pfcp_ie_destination_interface *destination_interface;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_redirect_information *redirect_information;
	struct pfcp_ie_outer_header_creation *outer_header_creation;
	struct pfcp_ie_transport_level_marking *transport_level_marking;
	struct pfcp_ie_forwarding_policy *forwarding_policy;
	struct pfcp_ie_header_enrichment *header_enrichment;
	struct pfcp_ie_traffic_endpoint_id *linked_traffic_endpoint_id;
	struct pfcp_ie_pfcpsm_req_flags *pfcpsm_req_flags;
	struct pfcp_ie_3gpp_interface_type *destination_interface_type;
};

/* Update Duplicating Parameters Grouped IE */
struct pfcp_ie_update_duplicating_parameters {
	/* Optional IEs */
	struct pfcp_ie_destination_interface *destination_interface;
	struct pfcp_ie_outer_header_creation *outer_header_creation;
	struct pfcp_ie_transport_level_marking *transport_level_marking;
	struct pfcp_ie_forwarding_policy *forwarding_policy;
};


/*
 *	PFCP Session Report Request Grouped IEs
 */

/* Downlink Data Report Grouped IE */
struct pfcp_ie_downlink_data_report {
	/* Optional IEs */
	struct pfcp_ie_pdr_id *pdr_id;
	struct pfcp_ie_downlink_data_service_information *downlink_data_service_information;
};

/* Error Indication Report Grouped IE */
struct pfcp_ie_error_indication_report {
	/* Mandatory IEs */
	struct pfcp_ie_f_teid *remote_f_teid;
	/* Optional IEs */
	struct pfcp_ie_pdr_id *pdr_id;
};

/* Packet Rate Status Report Grouped IE */
struct pfcp_ie_packet_rate_status_report {
	/* Mandatory IEs */
	struct pfcp_ie_qer_id *qer_id;
	struct pfcp_ie_packet_rate_status *packet_rate_status;
	/* Optional IEs */
	struct pfcp_ie_rate_control_status_per_qos_flow *rate_control_status_per_qos_flow;
};

/* Session Report Grouped IE */
struct pfcp_ie_session_report {
	/* Mandatory IEs */
	struct pfcp_ie_srr_id *srr_id;
	struct pfcp_ie_access_availability_report *access_availability_report;
	/* Optional IEs */
	struct pfcp_ie_qos_monitoring_report *qos_monitoring_report;
};

/* Update FAR Grouped IE */
struct pfcp_ie_update_far {
	/* Mandatory IEs */
	struct pfcp_ie_far_id *far_id;
	/* Optional IEs */
	struct pfcp_ie_apply_action *apply_action;
	struct pfcp_ie_update_forwarding_parameters *update_forwarding_parameters;
	struct pfcp_ie_update_duplicating_parameters *update_duplicating_parameters;
	struct pfcp_ie_bar_id *bar_id;
};

/* Update URR Grouped IE */
struct pfcp_ie_update_urr {
	/* Mandatory IEs */
	struct pfcp_ie_urr_id *urr_id;
	/* Optional IEs */
	struct pfcp_ie_measurement_method *measurement_method;
	struct pfcp_ie_reporting_triggers *reporting_triggers;
	struct pfcp_ie_measurement_period *measurement_period;
	struct pfcp_ie_volume_threshold *volume_threshold;
	struct pfcp_ie_volume_quota *volume_quota;
	struct pfcp_ie_time_threshold *time_threshold;
	struct pfcp_ie_time_quota *time_quota;
	struct pfcp_ie_event_threshold *event_threshold;
	struct pfcp_ie_event_quota *event_quota;
	struct pfcp_ie_quota_holding_time *quota_holding_time;
	struct pfcp_ie_dropped_dl_traffic_threshold *dropped_dl_traffic_threshold;
	struct pfcp_ie_quota_validity_time *quota_validity_time;
	struct pfcp_ie_monitoring_time *monitoring_time;
	struct pfcp_ie_subsequent_volume_threshold *subsequent_volume_threshold;
	struct pfcp_ie_subsequent_time_threshold *subsequent_time_threshold;
	struct pfcp_ie_subsequent_volume_quota *subsequent_volume_quota;
	struct pfcp_ie_subsequent_time_quota *subsequent_time_quota;
	struct pfcp_ie_subsequent_event_threshold *subsequent_event_threshold;
	struct pfcp_ie_subsequent_event_quota *subsequent_event_quota;
	struct pfcp_ie_inactivity_detection_time *inactivity_detection_time;
	struct pfcp_ie_linked_urr_id *linked_urr_id;
	struct pfcp_ie_measurement_information *measurement_information;
	struct pfcp_ie_time_quota_mechanism *time_quota_mechanism;
	struct pfcp_ie_aggregated_urrs *aggregated_urrs;
	struct pfcp_ie_far_id *far_id_for_quota_action;
	struct pfcp_ie_ethernet_inactivity_timer *ethernet_inactivity_timer;
	struct pfcp_ie_additional_monitoring_time *additional_monitoring_time;
	struct pfcp_ie_number_of_reports *number_of_reports;
};

/* Update QER Grouped IE */
struct pfcp_ie_update_qer {
	/* Mandatory IEs */
	struct pfcp_ie_qer_id *qer_id;
	/* Optional IEs */
	struct pfcp_ie_qer_correlation_id *qer_correlation_id;
	struct pfcp_ie_gate_status *gate_status;
	struct pfcp_ie_mbr *maximum_bitrate;
	struct pfcp_ie_gbr *guaranteed_bitrate;
	struct pfcp_ie_packet_rate *packet_rate;
	struct pfcp_ie_dl_flow_level_marking *dl_flow_level_marking;
	struct pfcp_ie_qfi *qos_flow_identifier;
	struct pfcp_ie_rqi *reflective_qos;
	struct pfcp_ie_paging_policy_indicator *paging_policy_indicator;
	struct pfcp_ie_averaging_window *averaging_window;
	struct pfcp_ie_qer_control_indications *qer_control_indications;
};

/* Update BAR Grouped IE */
struct pfcp_ie_update_bar {
	/* Mandatory IEs */
	struct pfcp_ie_bar_id *bar_id;
	/* Optional IEs */
	struct pfcp_ie_downlink_data_notification_delay *downlink_data_notification_delay;
	struct pfcp_ie_suggested_buffering_packets_count *suggested_buffering_packets_count;
};

/* Update Traffic Endpoint Grouped IE */
struct pfcp_ie_update_traffic_endpoint {
	/* Mandatory IEs */
	struct pfcp_ie_traffic_endpoint_id *traffic_endpoint_id;
	/* Optional IEs */
	struct pfcp_ie_f_teid *local_f_teid;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_ue_ip_address *ue_ip_address;
	struct pfcp_ie_framed_route *framed_route;
	struct pfcp_ie_framed_routing *framed_routing;
	struct pfcp_ie_framed_ipv6_route *framed_ipv6_route;
	struct pfcp_ie_qfi *qfi;
};

/* Update MAR Grouped IE */
struct pfcp_ie_update_mar {
	/* Mandatory IEs */
	struct pfcp_ie_mar_id *mar_id;
	/* Optional IEs */
	struct pfcp_ie_steering_functionality *steering_functionality;
	struct pfcp_ie_steering_mode *steering_mode;
};

/* Update SRR Grouped IE */
struct pfcp_ie_update_srr {
	/* Mandatory IEs */
	struct pfcp_ie_srr_id *srr_id;
	/* Optional IEs */
	struct pfcp_ie_access_availability_control_information *access_availability_control_information;
};

/* Query URR Grouped IE */
struct pfcp_ie_query_urr {
	/* Mandatory IEs */
	struct pfcp_ie_urr_id *urr_id;
};


/*
 *	PFCP Session Modification Response Grouped IEs
 */

/* Usage Report SMR Grouped IE */
struct pfcp_ie_usage_report {
	/* Mandatory IEs */
	struct pfcp_ie_urr_id *urr_id;
	struct pfcp_ie_ur_seqn *ur_seqn;
	struct pfcp_ie_usage_report_trigger *usage_report_trigger;
	/* Optional IEs */
	struct pfcp_ie_start_time *start_time;
	struct pfcp_ie_end_time *end_time;
	struct pfcp_ie_volume_measurement *volume_measurement;
	struct pfcp_ie_duration_measurement *duration_measurement;
	struct pfcp_ie_application_detection_information *application_detection_information;
	struct pfcp_ie_ue_ip_address *ue_ip_address;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_time_of_first_packet *time_of_first_packet;
	struct pfcp_ie_time_of_last_packet *time_of_last_packet;
	struct pfcp_ie_usage_information *usage_information;
	struct pfcp_ie_query_urr_reference *query_urr_reference;
	struct pfcp_ie_event_time_stamp *event_time_stamp;
	struct pfcp_ie_ethernet_traffic_information *ethernet_traffic_information;
};

/* Updated PDR Grouped IE */
struct pfcp_ie_updated_pdr {
	/* Mandatory IEs */
	struct pfcp_ie_pdr_id *pdr_id;
	/* Optional IEs */
	struct pfcp_ie_f_teid *local_f_teid;
	struct pfcp_ie_ue_ip_address *ue_ip_address;
};

#if 0
/* Additional Usage Reports Information Grouped IE */
struct pfcp_ie_additional_usage_reports_information {
	/* Mandatory IEs */
	struct pfcp_ie_auri *auri;
	/* Optional IEs */
	struct pfcp_ie_number_of_additional_usage_reports *number_of_additional_usage_reports;
};
#endif
