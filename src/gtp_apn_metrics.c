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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

#include "pppoe.h"
#include "gtp_apn.h"


static int
gtp_vrf_pppoe_metrics_tmpl_dump(FILE *fp, const char *apn_name,
				struct pppoe *pppoe)
{
	if (!pppoe)
		return -1;

	fprintf(fp, "%s{apn=\"%s\",interface=\"%s\"} %d\n"
		  , "gtpguard_pppoe_sessions_current"
		  , apn_name, pppoe->ifname, pppoe->session_count);
	return 0;
}

static int
gtp_vrf_pppoe_bundle_metrics_tmpl_dump(FILE *fp, const char *apn_name,
				       struct pppoe_bundle *bundle)
{
	int i;

	if (!bundle)
		return -1;

	for (i = 0; i < bundle->instance_idx; i++)
		gtp_vrf_pppoe_metrics_tmpl_dump(fp, apn_name
						  , bundle->pppoe[i]);
	return 0;
}

static int
gtp_apn_metrics_tmpl_dump(struct gtp_apn *apn, void *arg)
{
	FILE *fp = arg;
	struct ip_vrf *vrf = apn->vrf;

	if (!vrf || (!vrf->pppoe && !vrf->pppoe_bundle))
		return -1;

	gtp_vrf_pppoe_metrics_tmpl_dump(fp, apn->name, vrf->pppoe);
	gtp_vrf_pppoe_bundle_metrics_tmpl_dump(fp, apn->name
						 , vrf->pppoe_bundle);
	return 0;
}

int
gtp_apn_metrics_dump(FILE *fp)
{
	gtp_apn_foreach(gtp_apn_metrics_tmpl_dump, fp);
	return 0;
}
