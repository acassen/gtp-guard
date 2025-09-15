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
