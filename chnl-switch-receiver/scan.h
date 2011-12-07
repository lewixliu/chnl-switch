/*
 * Author: Marcin Harasimczuk
 *
 * Header file for application "scan".
 *
 */

#ifndef SCAN_H
#define SCAN_H

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include<unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

/* sysfs directory for PCI bus devices */
#define DEVICE_DIR "/sys/bus/pci/devices/"

/* Code of wireless device: 0x02 - Network controller, 0x80 - Other */ 
static const char wireless_dev[6] = "0x0280";

/* Names of interface types- the way they are defined in nl80211.h file */
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

/* Structure containing connection data */
struct conn_data {
	struct nl_handle *nl_sock;	// pointer to socket structure
	struct nl_cache *nl_cache;      // cache of address families
	struct genl_family *nl80211;    // generic netlink family pointer
};

// Initialise connection data
int conn_init( struct conn_data * );
// Clean connection data
void conn_clean( struct conn_data * );

#endif
