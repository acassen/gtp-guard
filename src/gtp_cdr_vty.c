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

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


static int gtp_config_cdr_write(vty_t *vty);
cmd_node_t cdr_node = {
	.node = CDR_NODE,
	.parent_node = CONFIG_NODE,
	.prompt ="%s(cdr-spool)# ",
	.config_write = gtp_config_cdr_write,
};

/*
 *	CDR Commands
 */
DEFUN(cdr_spool,
      cdr_spool_cmd,
      "cdr-spool STRING",
      "Configure CDR Spool\n"
      "Spool name")
{
	gtp_cdr_spool_t *new;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	new = gtp_cdr_spool_get(argv[0]);
	if (new) {
		vty->node = CDR_NODE;
		vty->index = new;
		gtp_cdr_spool_put(new);
		return CMD_SUCCESS;
	}

	new = gtp_cdr_spool_alloc(argv[0]);
	vty->node = CDR_NODE;
	vty->index = new;
	__set_bit(GTP_CDR_SPOOL_FL_SHUTDOWN_BIT, &new->flags);
	return CMD_SUCCESS;
}

DEFUN(no_cdr_spool,
      no_cdr_spool_cmd,
      "no cdr-spool STRING",
      "Destroy CDR Spool\n"
      "Spool Name")
{
	gtp_cdr_spool_t *s;
	int err;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	s = gtp_cdr_spool_get(argv[0]);
	if (!s) {
		vty_out(vty, "%% unknown cdr-spool %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_cdr_spool_put(s);
	err = gtp_cdr_spool_destroy(s);
	if (err) {
		vty_out(vty, "%% cdr-spool is used by at least one APN%s", VTY_NEWLINE);
		return CMD_WARNING;

	}

	return CMD_SUCCESS;
}

DEFUN(cdr_document_root,
      cdr_document_root_cmd,
      "document-root STRING",
      "Configure Docuement Root\n"
      "Path")
{
	gtp_cdr_spool_t *s = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(s->document_root, argv[0], GTP_PATH_MAX_LEN);
	return CMD_SUCCESS;
}

DEFUN(cdr_archive_root,
      cdr_archive_root_cmd,
      "archive-root STRING",
      "Configure Archive Root\n"
      "Path")
{
	gtp_cdr_spool_t *s = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(s->archive_root, argv[0], GTP_PATH_MAX_LEN);
	return CMD_SUCCESS;
}

DEFUN(cdr_file_prefix,
      cdr_file_prefix_cmd,
      "file prefix STRING",
      "Configure CDR File prefix\n"
      "Prefix name")
{
	gtp_cdr_spool_t *s = vty->index;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsd_strlcpy(s->prefix, argv[0], GTP_PATH_MAX_LEN);
	return CMD_SUCCESS;
}

DEFUN(cdr_file_roll_period,
      cdr_file_roll_period_cmd,
      "file roll-period <60-14400>",
      "Configure CDR File Roll period\n"
      "Number of seconds")
{
	gtp_cdr_spool_t *s = vty->index;
	int sec;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Number of seconds", sec, argv[0], 60, 14400);
	s->roll_period = sec;
	return CMD_SUCCESS;
}

DEFUN(cdr_file_size,
      cdr_file_size_cmd,
      "file size <10-1000>",
      "Configure CDR File size\n"
      "Number of MBytes")
{
	gtp_cdr_spool_t *s = vty->index;
	int size;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Number of MBytes", size, argv[0], 10, 1000);
	s->cdr_file_size = size*1024*1024;
	return CMD_SUCCESS;
}

DEFUN(cdr_file_async_io,
      cdr_file_async_io_cmd,
      "file async-io",
      "Configure CDR File Async I/O mode\n")
{
	gtp_cdr_spool_t *s = vty->index;

	__set_bit(GTP_CDR_SPOOL_FL_ASYNC_BIT, &s->flags);
	return CMD_SUCCESS;
}

DEFUN(cdr_file_owner,
      cdr_file_owner_cmd,
      "file owner uid INTEGER gid INTEGER",
      "Configure CDR File Ownership\n"
      "file owner"
      "User ID"
      "Integer"
      "Group ID"
      "Integer")
{
	gtp_cdr_spool_t *s = vty->index;
	char *endptr = NULL;
	int value;

	if (argc < 2) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	value = strtol(argv[0], &endptr, 10);
	if (value < 0 || *endptr != '\0') {
		vty_out(vty, "%% uid is malformed%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	s->user = value;

	value = strtol(argv[1], &endptr, 10);
	if (value < 0 || *endptr != '\0') {
		vty_out(vty, "%% gid is malformed%s", VTY_NEWLINE);
		s->user = 0;
		return CMD_WARNING;
	}
	s->group = value;

	if (s->user && s->group)
		__set_bit(GTP_CDR_SPOOL_FL_OWNER_BIT, &s->flags);
	return CMD_SUCCESS;
}

DEFUN(cdr_max_queue_size,
      cdr_max_queue_size_cmd,
      "max-queue-size <10-65536>",
      "Configure Maximum CDR queue retention size\n"
      "Number of CDR")
{
	gtp_cdr_spool_t *s = vty->index;
	int size;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	VTY_GET_INTEGER_RANGE("Number of CDR", size, argv[0], 10, 35536);
	s->q_max_size = size;
	return CMD_SUCCESS;
}

DEFUN(cdr_shutdown,
      cdr_shutdown_cmd,
      "shutdown",
      "Shutdown CDR spool\n")
{
	gtp_cdr_spool_t *s = vty->index;

	if (__test_bit(GTP_CDR_SPOOL_FL_SHUTDOWN_BIT, &s->flags)) {
		vty_out(vty, "%% spood:%s is already shutdown%s"
			   , s->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	gtp_cdr_spool_stop(s);
	__set_bit(GTP_CDR_SPOOL_FL_SHUTDOWN_BIT, &s->flags);
	return CMD_SUCCESS;
}

DEFUN(cdr_no_shutdown,
      cdr_no_shutdown_cmd,
      "no shutdown",
      "Activate CDR spool\n")
{
	gtp_cdr_spool_t *s = vty->index;
	int err;

	if (!__test_bit(GTP_CDR_SPOOL_FL_SHUTDOWN_BIT, &s->flags)) {
		vty_out(vty, "%% spood:%s is already running%s"
			   , s->name
			   , VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!s->document_root[0]) {
		vty_out(vty, "%% document-root MUST be configured first%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	err = gtp_cdr_spool_start(s);
	if (!err)
		__clear_bit(GTP_CDR_SPOOL_FL_SHUTDOWN_BIT, &s->flags);
	return CMD_SUCCESS;
}

DEFUN(show_cdr,
      show_cdr_cmd,
      "show cdr-spool [STRING]",
      SHOW_STR
      "CDR Spool\n"
      "Spool name")
{
	gtp_cdr_spool_t *s;

	if (argc < 1) {
		vty_out(vty, "%% missing arguments%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	s = gtp_cdr_spool_get(argv[0]);
	if (!s) {
		vty_out(vty, "%% unknown cdr-spool %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, " Pending in Queue : %d%s", s->q_len, VTY_NEWLINE);
	vty_out(vty, "        CDR count : %ld%s", s->cdr_count, VTY_NEWLINE);
	vty_out(vty, "        CDR bytes : %ld%s", s->cdr_bytes, VTY_NEWLINE);
	gtp_cdr_spool_put(s);
	return CMD_SUCCESS;
}

/* Configuration writer */
static int
gtp_config_cdr_write(vty_t *vty)
{
	list_head_t *l = &daemon_data->gtp_cdr;
	gtp_cdr_spool_t *s;

	list_for_each_entry(s, l, next) {
		vty_out(vty, "cdr-spool %s%s", s->name, VTY_NEWLINE);
		vty_out(vty, " document-root %s%s", s->document_root, VTY_NEWLINE);
		if (s->archive_root[0])
			vty_out(vty, " archive-root %s%s", s->archive_root, VTY_NEWLINE);
		if (s->prefix[0])
			vty_out(vty, " file prefix %s%s", s->prefix, VTY_NEWLINE);
		if (s->roll_period != GTP_CDR_DEFAULT_ROLLPERIOD)
			vty_out(vty, " file roll-period %d%s", s->roll_period, VTY_NEWLINE);
		if (__test_bit(GTP_CDR_SPOOL_FL_ASYNC_BIT, &s->flags))
			vty_out(vty, " file async-io%s", VTY_NEWLINE);
		if (__test_bit(GTP_CDR_SPOOL_FL_OWNER_BIT, &s->flags))
			vty_out(vty, " file owner uid %d gid %d%s"
				   , s->user, s->group, VTY_NEWLINE);
		if (s->q_max_size)
			vty_out(vty, " file max-queue-size %d%s", s->q_max_size, VTY_NEWLINE);
		vty_out(vty, " %sshutdown%s"
			   , __test_bit(GTP_CDR_SPOOL_FL_SHUTDOWN_BIT, &s->flags) ? "" : "no "
			   , VTY_NEWLINE);
		vty_out(vty, "!%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
gtp_cdr_vty_init(void)
{

	/* Install CDR commands. */
	install_node(&cdr_node);
	install_element(CONFIG_NODE, &cdr_spool_cmd);
	install_element(CONFIG_NODE, &no_cdr_spool_cmd);

	install_element(CDR_NODE, &cdr_document_root_cmd);
	install_element(CDR_NODE, &cdr_archive_root_cmd);
	install_element(CDR_NODE, &cdr_file_prefix_cmd);
	install_element(CDR_NODE, &cdr_file_roll_period_cmd);
	install_element(CDR_NODE, &cdr_file_size_cmd);
	install_element(CDR_NODE, &cdr_file_async_io_cmd);
	install_element(CDR_NODE, &cdr_file_owner_cmd);
	install_element(CDR_NODE, &cdr_max_queue_size_cmd);
	install_element(CDR_NODE, &cdr_shutdown_cmd);
	install_element(CDR_NODE, &cdr_no_shutdown_cmd);

	/* Install show commands. */
	install_element(VIEW_NODE, &show_cdr_cmd);
	install_element(ENABLE_NODE, &show_cdr_cmd);

	return 0;
}
