/**
 * @file cb_handlers.c 
 * @brief Implementation of callback handlers.
 *
 * @details Implementation of callbacks used for custom actions while receiving 
 * messages from nl80211 interface. 
 *
 * @author Marcin Harasimczuk
 *
 * @date 10.12.2011
 *
 */

#include "sniffer.h"

/**
 * @brief Handler called when netlink interface answers with an error.
 *
 * @warning override
 */
int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: error %d\n", err->error);
	*ret = 0;
	return NL_STOP;
}
/**
 * @brief Handler called in series of packets.
 *
 * @warning override
 */
int fin_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: finished\n");
	*ret = 0;
	return NL_SKIP;
}
/**
 * @brief Handler called when message has been accepted by netlink.
 *
 * @warning override
 */
int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: accepted\n");
	*ret = 0;
	return NL_STOP;
}
/**
 * @brief Handler called between received events.
 *
 * @warning override
 */
int no_seq_handler(struct nl_msg *msg, void *arg)
{
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: sequence\n");
	return NL_OK;
}

/**
 * @brief Handler for netlink family.
 *
 * @warning Should be in netlink API
 */
int family_handler(struct nl_msg *msg, void *arg)
{
	struct handler_args *grp = arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int rem_mcgrp;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

        if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
		struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

		nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
			  nla_data(mcgrp), nla_len(mcgrp), NULL);

		if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
			continue;
		if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
			    grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
			continue;
		grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	}
	
	return NL_SKIP;
}

/**
 * @brief Handler called when event is ready to be processed.
 *
 * @param msg   Message from interface.
 * @param arg   It is possible to pass additional arguments.
 */
int custom_event_handler(struct nl_msg *msg, void *arg)
{
        /* Generic netlink message header */
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        /* Buffer for attributes from netlink message */
	struct nlattr *msg_attr_buff[NL80211_ATTR_MAX + 1];
	struct event_handler_args *args = arg;
        
	if(CHNL_SWITCH_DEBUG)
		printf("custom_event_handler: entering\n");

        gettimeofday(&args->ts, NULL);
	unsigned long long usec = 1000000LL * args->ts.tv_sec + args->ts.tv_usec;	
	printf("%llu.%06llu\n", usec/1000000, usec % 1000000);
	args->have_ts = true;

        /* Extract attributes */
	nla_parse(msg_attr_buff, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
        
        /* Handle event according to type */
	switch (gnlh->cmd) 
        {
                /*
                 * Report TX status of a management frame transmitted with NL80211_CMD_FRAME. 
                 * NL80211_ATTR_COOKIE identifies the TX command and NL80211_ATTR_FRAME includes 
                 * the contents of the frame. NL80211_ATTR_ACK flag is included if the recipient 
                 * acknowledged the frame.
                 */
                case NL80211_CMD_FRAME_TX_STATUS:
                        break;
                /*
                 * Management frame TX request and RX notification. This command is used both as a request 
                 * to transmit a management frame and as an event indicating reception of a frame that was 
                 * not processed in kernel code, but is for us (i.e., which may need to be processed in a 
                 * user space application). NL80211_ATTR_FRAME is used to specify the frame contents 
                 * (including header). NL80211_ATTR_WIPHY_FREQ 
                 * (and optionally NL80211_ATTR_WIPHY_CHANNEL_TYPE) is used to indicate on which channel 
                 * the frame is to be transmitted or was received. If this channel is not the current 
                 * channel (remain-on-channel or the operational channel) the device will switch to the 
                 * given channel and transmit the frame, optionally waiting for a response for the time 
                 * specified using NL80211_ATTR_DURATION. When called, this operation returns a cookie 
                 * (NL80211_ATTR_COOKIE) that will be included with the TX status event pertaining to the 
                 * TX request. NL80211_ATTR_TX_NO_CCK_RATE is used to decide whether to send the management 
                 * frames at CCK rate or not in 2GHz band. 
                 */
                case NL80211_CMD_FRAME:
                        if(msg_attr_buff[NL80211_ATTR_FRAME])
                                args->handle_frame(msg_attr_buff[NL80211_ATTR_FRAME]);
                        break;
                default:
                        printf("unknown event %d\n", gnlh->cmd);
                        break;
	}
	
	if(CHNL_SWITCH_DEBUG)
		printf("custom_event_handler: end\n");

	/*fflush(stdout);*/
	return NL_SKIP;
}
