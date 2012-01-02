/** 
 * @file sniffer.h
 * @brief Main header for chnl-switch-sniffer.
 *
 * @details Netlink communication structures and functions.
 *
 * @author Marcin Harasimczuk
 *
 * @date 10.12.2011
 *
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#include <asm/errno.h> 
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/genetlink.h>
#include <sys/time.h>
#include <stdbool.h>

/** @brief Debug flag */
#define CHNL_SWITCH_DEBUG 1

/** @brief arguments of handler @warning override */
struct handler_args {
	const char *group;
	int id;
};

/** 
 * @brief Structure containing netlink connection data 
 */
struct conn_data 
{
        /** Socket */
	struct nl_handle *nl_sock;
        /** Cache of address families */
	struct nl_cache *nl_cache;
        /** Generic netlink family */
	struct genl_family *nl80211;
};

struct event_handler_args
{
   	struct timeval ts;
	bool have_ts;
	bool frame, time, reltime;
        void (*handle_frame)(struct nlattr *nl_frame);
};

/* Prototypes for counter */
void handle_frame( struct nlattr *nl_frame );

/* Prototypes for cb_handlers */
int err_handler( struct sockaddr_nl * , struct nlmsgerr * , void * );
int fin_handler( struct nl_msg * , void * );
int ack_handler( struct nl_msg * , void * );
int no_seq_handler(struct nl_msg * , void * );
int family_handler(struct nl_msg *, void * );
int custom_event_handler(struct nl_msg * , void * );


/* Prototypes for sniffer */
int conn_init( struct conn_data * );

int listen_events_init( struct conn_data * );
__u32 listen_events( struct conn_data *, void (*fptr_handle_frame)(struct nlattr *nl_frame) );

int mgmt_register( struct conn_data *, char *, __u16 );

void conn_clean( struct conn_data * );


#endif
