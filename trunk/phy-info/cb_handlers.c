/*
 * Author: Marcin Harasimczuk
 *
 * Callback handlers used while recieving messages. 
 * err, fin and ack handler control the flow of recieving.
 * my_cb_handler is for parsing and printing data from messages
 * to the standard output.
 */

/* called on error */
static int err_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	printf("err\n");
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

	// Bands
	nla_for_each_nested(pbnd, msg_attr_buff[NL80211_ATTR_WIPHY_BANDS], rem_bnd) 
	{                      
               	printf("	band %d:\n", id_bnd);
		printf("	------------------------------------------------\n");
        	id_bnd++;

		/* Parse bands */
                nla_parse(bnd_attr_buff, NL80211_BAND_ATTR_MAX, nla_data(pbnd),
                          nla_len(pbnd), NULL);
		
		// Bitrates in band
		printf("		----------------------------------------\n");
                printf("                bitrates:\n");
		printf("		----------------------------------------\n");

                nla_for_each_nested(pbtr, bnd_attr_buff[NL80211_BAND_ATTR_RATES], rem_btr)
                {
                        /* parse bitrates */
                        nla_parse(btr_attr_buff, NL80211_BITRATE_ATTR_MAX, nla_data(pbtr),
                                nla_len(pbtr), btr_policy);

                        // useless - skip
                        if(!btr_attr_buff[NL80211_BITRATE_ATTR_RATE])
                                continue;

                        /* bitrate is in [100 kbps] */
                        printf("                        ");
                        printf("%2.2f Mbps", 0.1 * nla_get_u32(btr_attr_buff[NL80211_BITRATE_ATTR_RATE]));

                        if(nla_get_u32(btr_attr_buff[NL80211_BITRATE_ATTR_RATE]) < 99)
                                printf(" ");

                        printf(" ; short preamble: ");
                        if(btr_attr_buff[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE])
                                printf(" OK\n");
                        else
                                printf(" -\n");

                }
		
		// Frequencies in band
		printf("		----------------------------------------\n");
		printf("		frequencies:\n");
		printf("		----------------------------------------\n");
		
		nla_for_each_nested(pfrq, bnd_attr_buff[NL80211_BAND_ATTR_FREQS], rem_frq) 
		{
			uint32_t frq;
			/* Parse frequencies */
			nla_parse(frq_attr_buff, NL80211_FREQUENCY_ATTR_MAX, nla_data(pfrq), 
				  nla_len(pfrq), frq_policy);
			
			// useless - skip
			if(!frq_attr_buff[NL80211_FREQUENCY_ATTR_FREQ])
				continue;
			
			frq = nla_get_u32(frq_attr_buff[NL80211_FREQUENCY_ATTR_FREQ]);
			printf("			%d MHz\n", frq);
		}
	
		// Supported types of interface
		printf("	------------------------------------------------\n");
		printf("	avalible interface types:\n");
		printf("	------------------------------------------------\n");
		
		if(msg_attr_buff[NL80211_ATTR_SUPPORTED_IFTYPES])
		{
			nla_for_each_nested(pmod, msg_attr_buff[NL80211_ATTR_SUPPORTED_IFTYPES] ,rem_mod)	
			{
				printf("		");
				/* nla_type in nlattr is of type enum nl80211_iftype */
				printf("%s\n", if_types[pmod->nla_type]);
			}
		}	
	printf("--------------------------------------------------------\n");
	}

	return NL_SKIP;

}
