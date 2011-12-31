/* 
 * @file sniffer.c
 * @brief Main chnl-switch-sniffer file.
 * 
 * @details Sniffer initializes netlink sockets to listen for chosen events/frames
 * 
 * @author Marcin Harasimczuk
 *
 * @date 11.12.2011
 *
 */

#include <asm/errno.h>
#include <stdio.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/genetlink.h>
#include <string.h>
#include <net/if.h>

#include "sniffer.h"
#include "usr_iface.h"

/** 
 * @brief Should be availble in netlink API
 * @warning possible override
 */
int nl_get_multicast_id(struct nl_handle *sock, const char *family, const char *group)
{
        /* Netlink message */
	struct nl_msg *msg;
        /* Callback */
	struct nl_cb *cb;
	int ret, ctrlid;
	
	/* This rises pedantic warnigs but is allowed under C99 */
	struct handler_args grp = {
		.group = group,
		.id = -ENOENT,
	};

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		ret = -ENOMEM;
		goto out_fail_cb;
	}

	ctrlid = genl_ctrl_resolve(sock, "nlctrl");

        genlmsg_put(msg, 0, 0, ctrlid, 0,
		    0, CTRL_CMD_GETFAMILY, 0);

	ret = -ENOBUFS;
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto out;

	ret = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, err_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, family_handler, &grp);

	while (ret > 0)
		nl_recvmsgs(sock, cb);

	if (ret == 0)
		ret = grp.id;
 nla_put_failure:
 out:
	nl_cb_put(cb);
 out_fail_cb:
	nlmsg_free(msg);
	return ret;
}

/**
 * @brief Initialize connection data structure
 */
int conn_init( struct conn_data *cd )
{
        /* Return value for functions */
	int error = 0;

	
	if(CHNL_SWITCH_DEBUG)
		printf("conn_init: entering\n");

	/* Allocate socket (prev: handle) */
	cd->nl_sock = nl_handle_alloc();
	if(!cd->nl_sock)
	{	
		fprintf(stderr, "cannot allocate socket\n");
		return -1;
	}

	/* Connect to generic netlink */
	error = genl_connect(cd->nl_sock);
	if(error)
	{
		fprintf(stderr, "cannot connect to netlink - clean!\n");
		nl_handle_destroy(cd->nl_sock);
		return -2;	
	}

	/* Allocate generic netlink cache */
	cd->nl_cache = genl_ctrl_alloc_cache(cd->nl_sock);
	if(!cd->nl_cache)
	{
		fprintf(stderr, "failed to allocate netlink cache! - clean!\n");
		nl_handle_destroy(cd->nl_sock);
		return -3;
	}

	/* Set netlink family - find if exists */
	cd->nl80211 = genl_ctrl_search_by_name(cd->nl_cache, "nl80211");
	if(!cd->nl80211)
	{
		fprintf(stderr, "nl80211 not present! - clean!\n");
		nl_cache_free(cd->nl_cache);
		nl_handle_destroy(cd->nl_sock);
		return -4;
	}
	
	if(CHNL_SWITCH_DEBUG)
		printf("conn_init: end\n");
	
	return 0;
}

/** 
 * @brief Register connection data for nl80211 events.
 *
 * @pre Initialize connection data first.
 */
int listen_events_init( struct conn_data *cd )
{
        /* ID of found multicast group */
	int multicast_id;
        /* Return value for functions */
        int ret;

	if(CHNL_SWITCH_DEBUG)
		printf("listen_events_init: entering\n");

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

	if(CHNL_SWITCH_DEBUG)
		printf("listen_events_init: end\n");	

	return 0;
}

/**
 * @brief Wait for events 
 *
 * @pre Initialize connection data for event listening.
 */
__u32 listen_events( struct conn_data *cd )
{
        /* Default callback */
	struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
        /* Command */
	__u32 command; 

	if(CHNL_SWITCH_DEBUG)
		printf("listen_events: entering\n");	

	if (!cb) 
        {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		return -ENOMEM;
	}

	/* no sequence checking for multicast messages */
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_handler, NULL);
        /* set custom event handler */
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, custom_event_handler, NULL);

	command = 0;

	while (!command)
	{
		nl_recvmsgs(cd->nl_sock, cb);
	}

	nl_cb_put(cb);
		
	if(CHNL_SWITCH_DEBUG)
		printf("listen_events: end\n");
	
	return command;
}

/**
 * @brief Register Management frame type/subtype for processing in userspace
 *
 * @pre Initialize connection data
 *
 * @param cd            Connection data
 * @param if_name       Interface name (eg. "wlan0")
 * @param fr_type       Frame type (eg. 0x0040)
 *
 */
int mgmt_register( struct conn_data *cd, char *if_name, __u16 fr_type )
{
	/* Callback */
	struct nl_cb *cb;
        /* Callback - new version */
	struct nl_cb *s_cb;
        /* Message to send */
	struct nl_msg *msg;
        /* Return value of functions */
	int error;
        /* Device ID of if_name */
	int devid = 0;  


	if(CHNL_SWITCH_DEBUG)
		printf("mgmt_register: entering\n");
	
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
	
	/* Device interface index to use */
	devid = if_nametoindex(if_name);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devid);
        /* Register frame type/subtype */
        NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, fr_type);

        /* 
         * Frame match is the number of frame body bytes to match. I chose to match the first byte.
         * In case of Probe Requests it is equal to 0 (SSID parameter set).
         *
         * Update: 10.12.2011 - For MGMT frames match is NULL of length 0
         */
        NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, 0, NULL);       

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
	
	if(CHNL_SWITCH_DEBUG)
		printf("mgmt_register: end\n");	
	
nla_put_failure:
	return 0;
}

int roaming_init( struct conn_data *cd )
{
        int error;

        error = 0;

        /* Disassociate frame */
        error = mgmt_register(cd, "wlan0", 0x0100);
        if(error < 0)
                return error;

        /* Association response */
        error = mgmt_register(cd, "wlan0", 0x0010);
        if(error < 0)
                return error;

        return error;
}


/**
 * @brief Clean connection data
 */
void conn_clean( struct conn_data *cd )
{
			
	if(CHNL_SWITCH_DEBUG)
		printf("conn_clean: entering\n");
	
	genl_family_put(cd->nl80211);
	nl_cache_free(cd->nl_cache);
	nl_handle_destroy(cd->nl_sock);

	if(CHNL_SWITCH_DEBUG)
		printf("conn_clean: end\n");
	
}

/** @brief Main application flow */
int main(int argc, char **argv)
{
	/* Connection data ( netlink socket etc. ) */
	struct conn_data cd;
	/* Error returned */
	int error;

        /* File holding experiment output */
        FILE exp_fd;
        /* Roaming data */
        roaming_data rd;

	if(CHNL_SWITCH_DEBUG)
		printf("main: entering\n");	

	/* Initialize connection data */
	error = conn_init(&cd);
	if(error < 0) 
		return -1;
	
        /* Get user input: Experiment file */
        error = open_exp(&exp_fd);
        if(error <  0)
        {
                conn_clean(&cd);
                return -2;
        }

        /* Get user input: Roaming data */
        error = init_roaming_data(&rd);
        if(error < 0)
        {
                close_exp(&exp_fd);
                conn_clean(&cd);
                return -3;
        }

        /* Register roaming 802.11 data frames in kernel */
        error = roaming_init(&cd);
        if(error < 0)
        {
                close_exp(&exp_fd);
                conn_clean(&cd);
                clean_roaming_data(&rd);
                return -4;
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
		
	/* Cleanup */ 
	conn_clean(&cd);
	
	if(CHNL_SWITCH_DEBUG)
		printf("main: end\n");

	return 0;
}
