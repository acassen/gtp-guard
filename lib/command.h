/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Zebra configuration command interface routine
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#pragma once

#include <stdio.h>
#include "vector.h"
#include "vty.h"

/*
 *	command definition
 */
struct host {
	char			*name;			/* Host name of this router. */

	char			*password;		/* Password for vty interface. */

	char			*enable;		/* Enable password */

	int			lines;			/* System wide terminal lines. */

	char			*logfile;		/* Log filename. */

	char			*config;		/* config file name of this host */

	int			advanced;		/* Flags for services */

	const char		*motd;			/* Banner configuration. */
	char			*motdfile;
};

/* There are some command levels which called from command node. */
enum node_type {
	AUTH_NODE,					/* Authentication mode of vty interface. */
	VIEW_NODE,					/* View node. Default mode of vty interface. */
	AUTH_ENABLE_NODE,				/* Authentication mode for change enable. */
	ENABLE_NODE,					/* Enable node. */
	CONFIG_NODE,					/* Config node. Default mode of config file. */
	SERVICE_NODE,					/* Service node. */
	DEBUG_NODE,					/* Debug node. */
	CFG_LOG_NODE,					/* Configure the logging */

	PDN_NODE,					/* PDN daemon commands. */
	CDRFWD_NODE,					/* CDR-FWD commands. */
	BPF_PROG_NODE,					/* BPF prog commands. */
	CGN_NODE,					/* Carrier Grade NAT */
	INTERFACE_NODE,					/* Interface commands. */
	MIRROR_NODE,					/* Mirror commands. */
	PPPOE_NODE,					/* PPPoE commands. */
	PPPOE_BUNDLE_NODE,				/* PPPoE Bundle commands. */
	IP_VRF_NODE,					/* IP VRF commands. */
	APN_NODE,					/* APN commands. */
	CDR_NODE,					/* CDR commands. */
	GTP_PROXY_NODE,					/* GTP Proxy commands. */
	GTP_ROUTER_NODE,				/* GTP Router commands. */
	PFCP_PROXY_NODE,				/* PFCP Proxy commands. */
	PFCP_ROUTER_NODE,				/* PFCP Router commands. */

	VTY_NODE,					/* Vty node. */
};

/* Completion match types. */
enum match_type {
	no_match,
	extend_match,
	ipv4_prefix_match,
	ipv4_match,
	ipv6_prefix_match,
	ipv6_match,
	range_match,
	vararg_match,
	partly_match,
	exact_match
};

/* Node which has some commands and prompt string and configuration
 * function pointer . */
struct cmd_node {
	enum node_type		node;			/* Node index. */
	enum node_type		parent_node;		/* Parent Node index. */
	const char		*prompt;		/* Prompt character at vty interface. */
	int			(*config_write) (struct vty *);	/* Node's configuration write function */
	struct vector		*cmd_vector;		/* Vector of this node's command list. */
};

struct cmd_ext {
	struct cmd_node		*node;
	int (*install) (void);

	struct list_head	next;
};

/* Structure of command element. */
struct cmd_element {
	const char		*string;		/* Command specification by string. */
	int			(*func) (struct cmd_element *,
					 struct vty *, int, const char *[]);
	const char		*doc;			/* Documentation of this command. */
	int			daemon;			/* Daemon to which this command belong. */
	struct vector		*strvec;		/* Pointing out each description vector. */
	unsigned int		cmdsize;		/* Command index count. */
	char			*config;		/* Configuration string */
	struct vector		*subconfig;		/* Sub configuration string */
	uint8_t			attr;			/* Command attributes */
};

/* Command description structure. */
struct desc {
	char			*cmd;			/* Command string. */
	char			*str;			/* Command's description. */
};


/*
 *	Some defines
 */

enum {
	CMD_ATTR_HIDDEN = 1,
};

#define CMD_SUCCESS		0
#define CMD_WARNING		1
#define CMD_ERR_NO_MATCH	2
#define CMD_ERR_AMBIGUOUS	3
#define CMD_ERR_INCOMPLETE	4
#define CMD_ERR_EXEED_ARGC_MAX	5
#define CMD_ERR_NOTHING_TODO	6
#define CMD_COMPLETE_FULL_MATCH	7
#define CMD_COMPLETE_MATCH	8
#define CMD_COMPLETE_LIST_MATCH	9
#define CMD_SUCCESS_DAEMON	10

#define CMD_ARGC_MAX		256

#define IPV6_ADDR_STR		"0123456789abcdefABCDEF:.%"
#define IPV6_PREFIX_STR		"0123456789abcdefABCDEF:.%/"
#define STATE_START		1
#define STATE_COLON		2
#define STATE_DOUBLE		3
#define STATE_ADDR		4
#define STATE_DOT		5
#define STATE_SLASH		6
#define STATE_MASK		7

#define DECIMAL_STRLEN_MAX	10
#define INIT_MATCHVEC_SIZE	10


/*
 *	Some usefull macros
 */

/* helper defines for end-user DEFUN* macros */
#define DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attrs, dnum)	\
	struct cmd_element cmdname = {						\
		.string = cmdstr,						\
		.func = funcname,						\
		.doc = helpstr,							\
		.attr = attrs,							\
		.daemon = dnum,							\
	};

#define DEFUN_CMD_FUNC_DECL(funcname) \
	static int funcname(struct cmd_element *, struct vty *, int, const char *[]);

#define DEFUN_CMD_FUNC_TEXT(funcname)						\
	static int funcname(struct cmd_element *self __attribute__ ((unused)),	\
			    struct vty *vty __attribute__ ((unused)),		\
			    int argc __attribute__ ((unused)),			\
			    const char *argv[] __attribute__ ((unused)))

/* DEFUN for vty command interafce. Little bit hacky ;-). */
#define DEFUN(funcname, cmdname, cmdstr, helpstr)				\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, 0)		\
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, attr)			\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)		\
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUN_HIDDEN(funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_ATTR (funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

/* DEFUN_NOSH for commands that vtysh should ignore */
#define DEFUN_NOSH(funcname, cmdname, cmdstr, helpstr)				\
	DEFUN(funcname, cmdname, cmdstr, helpstr)

/* DEFSH for vtysh. */
#define DEFSH(daemon, cmdname, cmdstr, helpstr)					\
	DEFUN_CMD_ELEMENT(NULL, cmdname, cmdstr, helpstr, 0, daemon)

/* DEFUN + DEFSH */
#define DEFUNSH(daemon, funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, daemon)	\
	DEFUN_CMD_FUNC_TEXT(funcname)

/* DEFUN + DEFSH with attributes */
#define DEFUNSH_ATTR(daemon, funcname, cmdname, cmdstr, helpstr, attr)		\
	DEFUN_CMD_FUNC_DECL(funcname)						\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, daemon)	\
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUNSH_HIDDEN(daemon, funcname, cmdname, cmdstr, helpstr)		\
	DEFUNSH_ATTR (daemon, funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

/* ALIAS macro which define existing command's alias. */
#define ALIAS(funcname, cmdname, cmdstr, helpstr)				\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, 0)

#define ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr, attr)			\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)

#define ALIAS_HIDDEN(funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN, 0)

#define ALIAS_SH(daemon, funcname, cmdname, cmdstr, helpstr)			\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, daemon)

#define ALIAS_SH_HIDDEN(daemon, funcname, cmdname, cmdstr, helpstr)		\
	DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN, daemon)

#define CMD_OPTION(S)	((S[0]) == '[')
#define CMD_VARIABLE(S)	(((S[0]) >= 'A' && (S[0]) <= 'Z') || ((S[0]) == '<'))
#define CMD_VARARG(S)	((S[0]) == '.')
#define CMD_RANGE(S)	((S[0] == '<'))

#define CMD_IPV4(S)		((strcmp((S), "A.B.C.D") == 0))
#define CMD_IPV4_PREFIX(S)	((strcmp((S), "A.B.C.D/M") == 0))
#define CMD_IPV6(S)		((strcmp((S), "X:X::X:X") == 0))
#define CMD_IPV6_PREFIX(S)	((strcmp((S), "X:X::X:X/M") == 0))

/* Common descriptions. */
#define SHOW_STR "Show running system information\n"
#define IP_STR "IP information\n"
#define IPV6_STR "IPv6 information\n"
#define NO_STR "Negate a command or set its defaults\n"
#define CLEAR_STR "Reset functions\n"
#define DEBUG_STR "Debugging functions (see also 'undebug')\n"
#define UNDEBUG_STR "Disable debugging functions (see also 'debug')\n"
#define ROUTER_STR "Enable a routing process\n"
#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"
#define OUT_STR "Filter outgoing routing updates\n"
#define IN_STR  "Filter incoming routing updates\n"
#define V4NOTATION_STR "specify by IPv4 address notation(e.g. 0.0.0.0)\n"
#define IP6_STR "IPv6 Information\n"
#define SECONDS_STR "<1-65535> Seconds\n"
#define ROUTE_STR "Routing Table\n"
#define PREFIX_LIST_STR "Build a prefix list\n"

#define CONF_BACKUP_EXT ".sav"


/*
 *	Global vars
 */
extern struct cmd_element config_exit_cmd;
extern struct cmd_element config_help_cmd;
extern struct cmd_element config_list_cmd;
extern struct host host;
extern char *command_cr;


/*
 *	Prototypes
 */
void install_node(struct cmd_node *node);
void install_default(enum node_type ntype);
void install_element(enum node_type ntype, struct cmd_element *cmd);
void sort_node(void);
char *argv_concat(const char **argv, int argc, int shift);
struct vector *cmd_make_strvec(const char *string);
void cmd_free_strvec(struct vector *v);
struct vector *cmd_describe_command(struct vector *vline, struct vty *vty, int *status);
char **cmd_complete_command(struct vector *vline, struct vty *vty, int *status);
const char *cmd_prompt(enum node_type ntype);
int config_from_file(struct vty *vty, FILE *fp);
enum node_type node_parent(enum node_type ntype);
int cmd_execute_command(struct vector *vline, struct vty *vty, struct cmd_element **cmd,
			int vtysh);
int cmd_execute_command_strict(struct vector *vline, struct vty *vty,
			       struct cmd_element **cmd);
void cmd_ext_register(struct cmd_ext *ext);
void cmd_init(void);
void cmd_terminate(void);
char *host_config_file(void);
void host_config_set(char *filename);
