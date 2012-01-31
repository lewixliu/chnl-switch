/* 
 * Author: Marcin Harasimczuk
 * 
 * Contains main function ( program flow ).
 *
 */

#include <stdio.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>  
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "winject.h"
#include "cb_handlers.c"
#include "sysr.c"

int parse_mac(unsigned char *mac_out, char *mac_in)
{
	int i;

	for (i = 0; i < ETH_ADDR_LEN ; i++) {
		int temp;
		char *cp = strchr(mac_in, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}
		if (sscanf(mac_in, "%x", &temp) != 1)
			return -1;
		if (temp < 0 || temp > 255)
			return -1;

		mac_out[i] = temp;
		if (!cp)
			break;
		mac_in = cp;
	}
	if (i < ETH_ADDR_LEN - 1)
		return -1;

	return 0;
}

/* Initialise connection data structure */
int conn_init( struct conn_data *cd )
{
	int error = 0;
	
	/*
	 * INITIALISE NETLINK DATA
	 */

	// initialise socket
	cd->nl_sock = nl_handle_alloc();
	if(!cd->nl_sock)
	{	
		fprintf(stderr, "cannot allocate socket\n");
		return -1;
	}
	// connect to generic netlink
	error = genl_connect(cd->nl_sock);
	if(error)
	{
		fprintf(stderr, "cannot connect to netlink - clean!\n");
		nl_handle_destroy(cd->nl_sock);
		return -2;	
	}
	// allocate generic netlink cache
	cd->nl_cache = genl_ctrl_alloc_cache(cd->nl_sock);
	if(!cd->nl_cache)
	{
		fprintf(stderr, "failed to allocate netlink cache! - clean!\n");
		nl_handle_destroy(cd->nl_sock);
		return -3;
	}

	// set netlink family - find if exists
	cd->nl80211 = genl_ctrl_search_by_name(cd->nl_cache, "nl80211");
	if(!cd->nl80211)
	{
		fprintf(stderr, "nl80211 not present! - clean!\n");
		nl_cache_free(cd->nl_cache);
		nl_handle_destroy(cd->nl_sock);
		return -4;
	}
	
	return 0;
}

/* Clean connection data structure */
void conn_clean( struct conn_data *cd)
{	
		genl_family_put(cd->nl80211);
		nl_cache_free(cd->nl_cache);
		nl_handle_destroy(cd->nl_sock);
}
 
/* Main program flow */
int main(int argc, char **argv)
{
	// connection data
	struct conn_data cd;
	// callback
	struct nl_cb *cb;
	struct nl_cb *s_cb;
	// message
	struct nl_msg *msg;
	int error;
	int devid = 0;
        // interface
        char *if_name;
	// mac
        unsigned char dst[ETH_ADDR_LEN];
        // ssid
        char *ssid;
        // freq in MHz
        char *user_freq;
        char *end;

        /*
         * Parse user input
         */

        if(argc != 5)
        {
                fprintf(stderr, "usage: winject INTERFACE MAC SSID FREQ\n");
                return -1;
        }

        if_name = argv[1];

        error = parse_mac(dst, argv[2]);
        if(error)
        {
                fprintf(stderr, "unable to parse mac address\n");
                return -1;
        }
	
        ssid = argv[3];

	user_freq = argv[4];

        printf("winject %s %x:%x:%x:%x:%x:%x %s %s\n",
                        if_name,
                        dst[0], dst[1], dst[2], 
                        dst[3], dst[4], dst[5],
                        ssid,
                        user_freq);

	/*
	 * INITIALIZE CONNECTION
	 */ 
	error = conn_init(&cd);
	if(error < 0) 
		return -1;
	
	/*
   	 * PREPARE MESSAGE
         */
	
	// allocate message
	msg = nlmsg_alloc();
	if(!msg)
	{
		fprintf(stderr, "failed to allocate netlink message - clean!\n");
		conn_clean(&cd);
		return -2;
	}

	// allocate callbacks
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	s_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if(!cb || !s_cb)
	{
		fprintf(stderr, "failed to allocate netlink callbacks - clean!\n");
		nlmsg_free(msg);
		conn_clean(&cd);
		return -3;
	}

	/*
         * BUILD MESSAGE
         */
	
	// Trigger Disassociation
	genlmsg_put(msg, 0, 0, genl_family_get_id(cd.nl80211), 0, 0, NL80211_CMD_DISASSOCIATE, 0);
	
	// Interface 
	devid = if_nametoindex(if_name);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devid);

        // MAC
        NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ADDR_LEN, dst);

        // SSID
        NLA_PUT(msg, NL80211_ATTR_SSID, strlen(ssid), ssid);

	// FREQ
        freq = strtoul(user_freq, &end, 10);
        if(*end == '\0')
        {
	        NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
        }
        else
        {
                printf("error: Unable to parse frequency\n");
                nl_cb_put(cb);
		nlmsg_free(msg);
		conn_clean(&cd);
                exit(-1);
        }
        
	//Added in new
	nl_socket_set_cb(cd.nl_sock, s_cb);
		
	/*
	 * SEND MESSAGE
 	 */	
	error = nl_send_auto_complete(cd.nl_sock, msg);
	if(error < 0)
	{
		printf("err!");	
		fprintf(stderr, "cannot send message! - clean!\n");
		nl_cb_put(cb);
		nlmsg_free(msg);
		conn_clean(&cd);
		return -4;
	}
	/*
	 * RECIEVE MESSAGE
	 */
	/* Callbacks control the receiving of messages (NL_SKIP, NL_STOP).
	 * Callbacks set error as 0 if there are no more messages to be
	 * expected.
	 */
	error = 1;
	nl_cb_err(cb, NL_CB_CUSTOM, err_handler, &error);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, fin_handler, &error);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &error);
	// wait for response
	while(error > 0)
		nl_recvmsgs(cd.nl_sock, cb);

	nl_cb_put(cb);
	nlmsg_free(msg);
	
	// cleanup 
	conn_clean(&cd);
	
nla_put_failure:
	return 0;
}
