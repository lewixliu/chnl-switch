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

/* Utility form Johannes Berg project "iw" */
#define DIV_ROUND_UP(x, y) (((x) + (y - 1)) / (y))

int parse_hex_mask(char *hexmask, unsigned char **result, size_t *result_len,
		   unsigned char **mask)
{
	size_t len = strlen(hexmask) / 2;
	unsigned char *result_val;
	unsigned char *result_mask = NULL;

	int pos = 0;

	*result_len = 0;

	result_val = calloc(len + 2, 1);
	if (!result_val)
		goto error;
	*result = result_val;
	if (mask) {
		result_mask = calloc(DIV_ROUND_UP(len, 8) + 2, 1);
		if (!result_mask)
			goto error;
		*mask = result_mask;
	}

	while (1) {
		char *cp = strchr(hexmask, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}

		if (result_mask && (strcmp(hexmask, "-") == 0 ||
				    strcmp(hexmask, "xx") == 0 ||
				    strcmp(hexmask, "--") == 0)) {
			/* skip this byte and leave mask bit unset */
		} else {
			int temp, mask_pos;
			char *end;

			temp = strtoul(hexmask, &end, 16);
			if (*end)
				goto error;
			if (temp < 0 || temp > 255)
				goto error;
			result_val[pos] = temp;

			mask_pos = pos / 8;
			if (result_mask)
				result_mask[mask_pos] |= 1 << (pos % 8);
		}

		(*result_len)++;
		pos++;

		if (!cp)
			break;
		hexmask = cp;
	}

	return 0;
 error:
	free(result_val);
	free(result_mask);
	return -1;
}

unsigned char *parse_hex(char *hex, size_t *outlen)
{
	unsigned char *result;

	if (parse_hex_mask(hex, &result, outlen, NULL))
		return NULL;
	return result;
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
	// ies
	size_t ies_size;
	unsigned char *ies_data;
	struct nl_msg *ssids = NULL;
	struct nl_msg *freqs = NULL;
	
	// init for ies
	ssids = nlmsg_alloc();
	freqs = nlmsg_alloc();

	//@TODO check if allocated!
	

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
	
	// Trigger scan request
	genlmsg_put(msg, 0, 0, genl_family_get_id(cd.nl80211), 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
	
	//@TODO: Add attr devid
	devid = if_nametoindex("wlan0");
	printf("devid(%d)", devid);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devid);
	
	//@TODO: Command handler
	// freq
	NLA_PUT_U32(freqs, 1, 2412);
	// Add ies
	NLA_PUT(msg, NL80211_ATTR_IE, 64, "123456");
	//ssids
	NLA_PUT(ssids, 1, 0, "");
	nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);
	nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);

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
