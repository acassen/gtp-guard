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
	struct pfcp_ie *h;
	/* Optional IEs */
	struct pfcp_ie_pfd_contents *pfd_contents;
};

struct pfcp_ie_application_id_pfds {
	struct pfcp_ie *h;
	/* Mandatory IEs */
	struct pfcp_ie_application_id *application_id;
	/* Optional IEs */
	struct pfcp_ie_pfd_context *pfd_context;
};

/*
 *	PFCP Association Setup Grouped IEs
 */
struct pfcp_ie_session_retention_information {
	struct pfcp_ie *h;
	struct pfcp_ie_cp_pfcp_entity_ip_address *cp_pfcp_entity_ip_address;
};

struct pfcp_ie_ue_ip_address_pool_information {
	struct pfcp_ie *h;
	struct pfcp_ie_ue_ip_address_pool_identity *ue_ip_address_pool_identity;
	struct pfcp_ie_network_instance *network_instance;
	struct pfcp_ie_s_nssai *s_nssai;
	struct pfcp_ie_ip_version *ip_version;
};

/*
 *	PFCP Association Update Grouped IEs
 */
struct pfcp_ie_gtp_u_path_qos_control_information {
	struct pfcp_ie *h;
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
	struct pfcp_ie *h;
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
	struct pfcp_ie *h;
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
