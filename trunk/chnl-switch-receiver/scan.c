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

#include "scan.h"
#include "cb_handlers.c"
#include "sysr.c"

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

/* Register connection data for nl80211 events */
int listen_events_init( struct conn_data *cd )
{
	int multicast_id;
        int ret;

	/* Get configuration multicast group ID */
	multicast_id = nl_get_multicast_id(cd->nl_sock, "nl80211", "config");
	if (multicast_id < 0)
		return multicast_id;
        
        /* Add membership to configuration multicast group */
	ret = nl_socket_add_membership(cd->nl_sock, multicast_id);
	if (ret)
		return ret;

	/* Scan multicast group */
	multicast_id = nl_get_multicast_id(cd->nl_sock, "nl80211", "scan");
	if (multicast_id >= 0) {
		ret = nl_socket_add_membership(cd->nl_sock, multicast_id);
		if (ret)
			return ret;
	}

	/* Regulatory multicast group */
	multicast_id = nl_get_multicast_id(cd->nl_sock, "nl80211", "regulatory");
	if (multicast_id >= 0) {
		ret = nl_socket_add_membership(cd->nl_sock, multicast_id);
		if (ret)
			return ret;
	}

	/* MLME multicast group */
	multicast_id = nl_get_multicast_id(cd->nl_sock, "nl80211", "mlme");
	if (multicast_id >= 0) {
		ret = nl_socket_add_membership(cd->nl_sock, multicast_id);
		if (ret)
			return ret;
	}

	return 0;
}

/* Wait for events */
__u32 listen_events( struct conn_data *cd )
{
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
	__u32 command; 

	if (!cb) 
        {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		return -1;	//-ENOMEM
	}

	/* no sequence checking for multicast messages */
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_handler, NULL);
        /* set custom event handler */
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, my_event_handler, NULL);

	command = 0;

	while (!command)
		nl_recvmsgs(cd->nl_sock, cb);

	nl_cb_put(cb);

	return command;
}

/* Register cd.nl_sock for processing Probe Request frames in userspace */
int mgmt_register( struct conn_data *cd )
{
	/* Callbacks */
	struct nl_cb *cb;       // Callback structure
	struct nl_cb *s_cb;     // Callback added in new version

        /* Message */
	struct nl_msg *msg;     // Message to send

        /* Helper */
	int error;              // Return value of used functions
	int devid = 0;          // Device interface index
	
	/* Allocate message */
	msg = nlmsg_alloc();
	if(!msg)
	{
		fprintf(stderr, "failed to allocate netlink message - clean!\n");
		return -1;
	}

	/* Allocate callbacks */
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	s_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if(!cb || !s_cb)
	{
		fprintf(stderr, "failed to allocate netlink callbacks - clean!\n");
		nlmsg_free(msg);
		return -2;
	}

	/*
         * Register for receiving certain mgmt frames (via NL80211_CMD_FRAME) for processing in userspace. 
         * This command requires an interface index, a frame type attribute (optional for backward
         * compatibility reasons, if not given assumes action frames) and a match attribute containing 
         * the first few bytes of the frame that should match, e.g. a single byte for only a category match 
         * or four bytes for vendor frames including the OUI. The registration cannot be dropped, but is 
         * removed automatically when the netlink socket is closed. Multiple registrations can be made. 
         */
	genlmsg_put(msg, 0, 0, genl_family_get_id(cd->nl80211), 0, 0, NL80211_CMD_REGISTER_FRAME, 0);
	
	/* Device interface index to use (hardcoded) */
	devid = if_nametoindex("wlan0");
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devid);

        /* I chose to receive Probe Request frames (code 0x04) */
        NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, 4);

        /* 
         * Frame match is the number of frame body bytes to match. I chose to match the first byte.
         * In case of Probe Requests it is equal to 0 (SSID parameter set).
         */
        NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, 1, 0);       

	/* Added in new version */
	nl_socket_set_cb(cd->nl_sock, s_cb);
		
	/* Send message */
	error = nl_send_auto_complete(cd->nl_sock, msg);
	if(error < 0)
	{
		printf("err!");	
		fprintf(stderr, "cannot send message! - clean!\n");
		nl_cb_put(cb);
                nl_cb_put(s_cb);
		nlmsg_free(msg);
		return -3;
	}
	
	/* 
         * Receive ACK from kernel.
         *
         * Callbacks control the receiving of messages (NL_SKIP, NL_STOP).
	 * Callbacks set error as 0 if there are no more messages to be
	 * expected.
	 */
	error = 1;
	nl_cb_err(cb, NL_CB_CUSTOM, err_handler, &error);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, fin_handler, &error);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &error);
	
        /* Wait for ACK */
	while(error > 0)
		nl_recvmsgs(cd->nl_sock, cb);

        /* Clean */
	nl_cb_put(cb);
        nl_cb_put(s_cb);
	nlmsg_free(msg);
	
nla_put_failure:
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
	/* Connection data ( netlink socket etc. ) */
	struct conn_data cd;

	/* Helper */
	int error;              // Return value from called functions
	
	/* Initialise connection data */
	error = conn_init(&cd);
	if(error < 0) 
		return -1;
	
        /* Register for MGMT Probe Request processing in user space */
        error = mgmt_register(&cd);
        if(error < 0)
        {
                conn_clean(&cd);
                return -2;
        }

        /* Prepare to listen to nl80211 events */
        error = listen_events_init(&cd);
        if(error < 0)
        {
                conn_clean(&cd);
                return -3;
        }

        /* Listen to events */
        listen_events(&cd);
		
	// cleanup 
	conn_clean(&cd);
	
nla_put_failure:
	return 0;
}
