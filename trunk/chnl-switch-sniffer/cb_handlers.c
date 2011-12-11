/**
 * @file cb_handlers.c 
 * Implementation of callback handlers.
 * Implementation of callbacks used for custom actions while receiving 
 * messages from nl80211 interface. 
 *
 * @author Marcin Harasimczuk
 *
 * @date 10.12.2011
 *
 *
 */

#include "sniffer.h"

/**
 * Handler called when netlink interface answers with an error.
 *
 * @warning override
 */
static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: error %d\n", err->error);
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}
/**
 * Handler called in series of packets
 *
 * @warning override
 */
static int fin_handler(struct nl_msg *msg, void *arg)
{
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: finished\n");
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}
/**
 * Handler called when message has been accepted by netlink
 *
 * @warning override
 */
static int ack_handler(struct nl_msg *msg, void *arg)
{
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: accepted\n");
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}
/**
 * Handler called between received events
 *
 * @warning override
 */
static int no_seq_handler(struct nl_msg *msg, void *arg)
{
        if(CHNL_SWITCH_DEBUG)
                printf("netlink message: sequence\n");
	return NL_OK;
}

/**
 * Handler called when event is ready to be processed
 *
 * @param msg   Message from interface
 * @param arg   It is possible to pass additional arguments
 */
static int custom_event_handler(struct nl_msg *msg, void *arg)
{
        /** Generic netlink message header */
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        /** Buffer for attributes from netlink message */
	struct nlattr *msg_attr_buff[NL80211_ATTR_MAX + 1];
        /** Frame TX status */
	__u16 status;
	
	if(CHNL_SWITCH_DEBUG)
		printf("custom_event_handler: entering\n");

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
                        printf("mgmt TX status (cookie %llx): %s\n",
                                (unsigned long long)nla_get_u64(msg_attr_buff[NL80211_ATTR_COOKIE]),
                                msg_attr_buff[NL80211_ATTR_ACK] ? "acked" : "no ack");
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
                        printf("Frame recieved!\n");
                        break;
                default:
                        printf("unknown event %d\n", gnlh->cmd);
                        break;
	}
	
	if(CHNL_SWITCH_DEBUG)
		printf("my_event_handler: end\n");

	//fflush(stdout);
	return NL_SKIP;
}
