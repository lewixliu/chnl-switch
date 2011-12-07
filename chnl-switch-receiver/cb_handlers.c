/*
 * Author: Marcin Harasimczuk
 *
 * Callback handlers used while recieving messages. 
 * err, fin and ack handler control the flow of recieving.
 * my_cb_handler is for parsing and printing data from messages
 * to the standard output.
 */

/* called on error */
static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	printf("err=%d\n", err->error);
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}
/* called for last packet in series of packets */
static int fin_handler(struct nl_msg *msg, void *arg)
{
	//printf("fin\n");
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}
/* called when ack is needed */
static int ack_handler(struct nl_msg *msg, void *arg)
{
	printf("ack\n");
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}
/* no sequence check handler for event receiver */
static int no_seq_handler(struct nl_msg *msg, void *arg)
{
	printf("seq\n");
	return NL_OK;
}

/* Custom handler for event notification */
static int my_event_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr_buff[NL80211_ATTR_MAX + 1];
	char ifname[100];
	__u16 status;
	
	if(CHNL_SWITCH_DEBUG)
		printf("my_event_handler: entering\n");

	nla_parse(msg_attr_buff, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (msg_attr_buff[NL80211_ATTR_IFINDEX] && msg_attr_buff[NL80211_ATTR_WIPHY]) {
		if_indextoname(nla_get_u32(msg_attr_buff[NL80211_ATTR_IFINDEX]), ifname);
		printf("%s (phy #%d): ", ifname, nla_get_u32(msg_attr_buff[NL80211_ATTR_WIPHY]));
	} else if (msg_attr_buff[NL80211_ATTR_IFINDEX]) {
		if_indextoname(nla_get_u32(msg_attr_buff[NL80211_ATTR_IFINDEX]), ifname);
		printf("%s: ", ifname);
	} else if (msg_attr_buff[NL80211_ATTR_WIPHY]) {
		printf("phy #%d: ", nla_get_u32(msg_attr_buff[NL80211_ATTR_WIPHY]));
	}

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

/* Custom callback handler for printing data form valid message */
static int my_cb_handler(struct nl_msg *msg, void *arg)
{
	/* Attribute pointers (loop counters) for expected nested attributes */
	struct nlattr *pbnd;		// band attribute
	struct nlattr *pfrq;		// frequency attribute
	struct nlattr *pbtr;		// bitrate attribute
	struct nlattr *pmod;		// mode attribute
	struct nlattr *pcmd;		// commands attribute
	
	/* Length of nested attributes stream (remaining) for loop */
	int rem_bnd; 
	int rem_frq;
	int rem_btr;
	int rem_mod;
	int rem_cmd;
	
	/* Attribute buffer for message */
	struct nlattr *msg_attr_buff[NL80211_ATTR_MAX + 1];
	/* Attribute buffer for attribute band nested attributes */
	struct nlattr *bnd_attr_buff[NL80211_BAND_ATTR_MAX + 1];
	/* Attribute buffer for attribute frequency nested attributes */
	struct nlattr *frq_attr_buff[NL80211_FREQUENCY_ATTR_MAX + 1];
	/* Attribute buffer for attribute bitrate nested attributes */
	struct nlattr *btr_attr_buff[NL80211_BITRATE_ATTR_MAX + 1];
	
	/* band identifier */
	int id_bnd = 0;
	
	/*
	 * Attribute policy (validation for parsing) 
	 *
	 * NL80211_FREQUENCY_ATTR_FREQ : frequency in MHz [32 bit integer] 
	 * NL80211_FREQUENCY_ATTR_DISABLED : channel disabled in current domain [bool]
	 * NL80211_FREQUENCY_ATTR_PASSIVE_SCAN : only passive scan on channel [bool]
	 * NL80211_FREQUENCY_ATTR_NO_IBSS : IBSS prohibitet on this channel [bool]
	 * NL80211_FREQUENCY_ATTR_RADAR : mandatory radar detection [bool]
	 * NL80211_FREQUENCY_ATTR_MAX_TX_POWER : max transmission power in 100*dBm [32 bit integer]
	 *
	 * NL80211_BITRATE_ATTR_RATE : bitrate in 100 kbps [32 bit integer]
	 * NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE : short preamble supported [bool]
 	 */
	static struct nla_policy frq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
                [NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
                [NL80211_FREQUENCY_ATTR_PASSIVE_SCAN] = { .type = NLA_FLAG },
                [NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
                [NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
                [NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
        };

	static struct nla_policy btr_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
                [NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
        };

	/* Set pointer (in message) at payload of netlink header. This message is a
         * generic netlink message so it will point to generic netlink header.
	 */
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	/* Parse message */
	nla_parse( msg_attr_buff,		// destination array with maxtype+1 elements
		   NL80211_ATTR_MAX,		// maximum attribute type to be expected
		   genlmsg_attrdata(gnlh, 0),	// head of attribute stream ( familly header size =0 )
		   genlmsg_attrlen(gnlh, 0), 	// length of attribute stream
		   NULL );			// validation policy			
	
	// NL80211_ATTR_WIPHY_BANDS is not optional.
	// if message lacks this attribute it is useless - skip to next message.
	if(!msg_attr_buff[NL80211_ATTR_WIPHY_BANDS])
		return NL_SKIP;

						
	printf("--------------------------------------------------------\n");
	printf("Phy ----------------------------------------------------\n");
	printf("--------------------------------------------------------\n");

	// Device name
	if (msg_attr_buff[NL80211_ATTR_WIPHY_NAME])
	{
               	printf("name: %s\n", nla_get_string(msg_attr_buff[NL80211_ATTR_WIPHY_NAME]));
		printf("--------------------------------------------------------\n");
	}

	return NL_SKIP;

}
