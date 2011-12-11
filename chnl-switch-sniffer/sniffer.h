/** 
 * @file sniffer.h
 * Main header for chnl-switch-sniffer.
 * Netlink communication structures and functions.
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

/** Debug flag */
#define CHNL_SWITCH_DEBUG 1

/** 
 * Names of interface types- the way they are defined in nl80211.h file 
 */
static const char *if_types[NL80211_IFTYPE_MAX+1] =
{
	"UNSPECIFIED",
	"AD-HOC",
	"STATION",
	"ACCESS POINT",
	"VLAN ACCESS POINT",
	"WDS",
	"MONITOR",
	"MESH POINT"
};

/** 
 * Structure containing netlink connection data 
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

/* Prototypes for sniffer */
int conn_init( struct conn_data * );

int listen_events_init( struct conn_data * );
__u32 listen_events( struct conn_data * );

int mgmt_register( struct conn_data *, char *, __u16 );

void conn_clean( struct conn_data * );

/* Prototypes for cb_handlers */


#endif
