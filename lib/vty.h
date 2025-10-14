/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Virtual terminal [aka TeletYpe] interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
 */
#pragma once

#include <errno.h>
#include <netinet/in.h>
#include "timer.h"
#include "thread.h"
#include "buffer.h"

#define VTY_BUFSIZ 512
#define VTY_MAXHIST 20
#define TELNET_NAWS_SB_LEN 5

enum vty_event {
	VTY_SERV,
	VTY_READ,
	VTY_WRITE,
	VTY_TIMEOUT_RESET
};

enum vty_type {
	VTY_TERM,
	VTY_FILE,
	VTY_SHELL,
	VTY_SHELL_SERV
};

enum vty_status {
	VTY_NORMAL,
	VTY_CLOSE,
	VTY_MORE,
	VTY_MORELINE,
	VTY_HOLD
};


/* VTY struct. */
struct vty {
	int			fd;				/* File descripter of this vty. */
	enum vty_type		type;				/* Is this vty connect to file or not */
	int			node;				/* Node status of this vty */
	int			fail;				/* Failure count */
	struct buffer		*obuf;				/* Output buffer */
	char			*buf;				/* Command input buffer */
	int			cp;				/* Command cursor point */
	int			length;				/* Command length */
	int			max;				/* Command max length */
	char			*hist[VTY_MAXHIST];		/* Histry of command */
	int			hp;				/* History lookup current point */
	int			hindex;				/* History insert end point */
	void			*index;				/* For current referencing point */
	void			*index_sub;			/* For multiple level index treatment such
								 * as key chain and key.
								 */
	unsigned char		escape;				/* For escape character. */
	enum vty_status		status;				/* Current vty status. */
	unsigned char		iac;				/* IAC handling: was the last character received
								 * the IAC (interpret-as-command) escape character
								 * (and therefore the next character will be the
								 * command code)?  Refer to Telnet RFC 854.
								 */
	unsigned char		iac_sb_in_progress;		/* IAC SB (option subnegotiation) handling */
	unsigned char		sb_buf[TELNET_NAWS_SB_LEN];	/* At the moment, we care only about the NAWS
								 * (window size) negotiation, and that requires
								 * just a 5-character buffer (RFC 1073):
								 * <NAWS char> <16-bit width> <16-bit height>
								 */
	size_t			sb_len;				/* How many subnegotiation characters have we
								 * received?  We just drop those that do not
								 * fit in the buffer.
								 */
	int			width;				/* Window width */
	int			height;				/* Window height */
	int			lines;				/* Configure lines */
	int			monitor;			/* Terminal monitor */
	int			config;				/* In configure mode */
	struct thread_master	*master;			/* Master thread */
	struct thread		*t_read;			/* Read thread */
	struct thread		*t_write;			/* Write thread */
	unsigned long		v_timeout;			/* Timeout seconds */
	struct thread		*t_timeout;			/* Timeout thread */
	struct sockaddr_storage	address;			/* What address is this vty comming from. */
};

/* Small macro to determine newline is newline only or linefeed needed. */
#define VTY_NEWLINE	((vty->type == VTY_TERM) ? "\r\n" : "\n")

/* Default time out value */
#define VTY_TIMEOUT_DEFAULT	600
#define VTY_IO_TIMEOUT		(10 * TIMER_HZ)

/* Vty read buffer size. */
#define VTY_READ_BUFSIZ 512

/* Directory separator. */
#define DIRECTORY_SEP '/'
#define IS_DIRECTORY_SEP(c) ((c) == DIRECTORY_SEP)

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif

/* Utility macros to convert VTY argument to unsigned long or integer. */
#define VTY_GET_LONG(NAME,V,STR)					\
do {									\
  char *endptr = NULL;							\
  errno = 0;								\
  (V) = strtoul((STR), &endptr, 10);					\
  if (*(STR) == '-' || *endptr != '\0' || errno) {			\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
} while (0)

#define VTY_GET_INTEGER_RANGE(NAME,V,STR,MIN,MAX)			\
do {									\
  unsigned long tmpl;							\
  VTY_GET_LONG(NAME, tmpl, STR);					\
  if ((tmpl < (MIN)) || (tmpl > (MAX))) {				\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
  (V) = tmpl;								\
} while (0)

#define VTY_GET_INTEGER(NAME,V,STR) \
	VTY_GET_INTEGER_RANGE(NAME,V,STR,0U,UINT32_MAX)

#define VTY_GET_IPV4_ADDRESS(NAME,V,STR)				\
do {									\
  int retv;								\
  retv = inet_aton((STR), &(V));					\
  if (!retv) {								\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
} while (0)

#define VTY_GET_IPV4_PREFIX(NAME,V,STR)					\
do {									\
  int retv;								\
  retv = str2prefix_ipv4((STR), &(V));					\
  if (retv <= 0) {							\
      vty_out(vty, "%% Invalid %s value%s", NAME, VTY_NEWLINE);		\
      return CMD_WARNING;						\
    }									\
} while (0)


/* Prototypes. */
void vty_init(void);
void vty_terminate(void);
int vty_listen(struct thread_master *m, struct sockaddr_storage *addr);
void vty_reset(void);
struct vty *vty_new(void);
int vty_out(struct vty *vty, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);
int vty_brd_out(const char *fmt, ...);
ssize_t vty_send_out(struct vty *vty, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);
void vty_prompt_hold(struct vty *vty);
void vty_prompt_restore(struct vty *vty);
int vty_read_config(char *config_file, char *config_default_dir);
void vty_time_print(struct vty *vty, int cr);
void vty_close(struct vty *vty);
char *vty_get_cwd(void);
int vty_config_lock(struct vty *vty);
int vty_config_unlock(struct vty *vty);
int vty_shell(struct vty *vty);
int vty_shell_serv(struct vty *vty);
void vty_hello(struct vty *vty);
