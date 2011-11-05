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
	// message
	struct nl_msg *msg;
	int error;


	/* 
   	 * Show sysfs information
	 */
	error = print_device_driver();
	if(error < 0)
		fprintf(stderr, "Cannot find driver information\n");
	
	
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
	if(!cb)
	{
		fprintf(stderr, "failed to allocate netlink callbacks - clean!\n");
		nlmsg_free(msg);
		conn_clean(&cd);
		return -3;
	}

	/*
         * BUILD MESSAGE
         */
	
	// dump request to get a list of all present wiphys.
	genlmsg_put(msg, 0, 0, genl_family_get_id(cd.nl80211), 0, NLM_F_DUMP, NL80211_CMD_GET_WIPHY, 0);

	/*
	 * PREPARE CALLBACK
	 */
	// register custom handler for callback
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, my_cb_handler, NULL);
		
				
	/*
	 * SEND MESSAGE
 	 */	
	error = nl_send_auto_complete(cd.nl_sock, msg);
	if(error < 0)
	{	
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

	return 0;
}
