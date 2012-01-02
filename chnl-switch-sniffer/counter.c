#include "sniffer.h"

#define ADDR_LEN 6

void parse_mac_addr(char *parsed_mac, unsigned char *mac_addr)
{
	int i, l;

	l = 0;
	for (i = 0; i < ADDR_LEN; i++) {
		if (i == 0) {
			sprintf(parsed_mac+l, "%02x", mac_addr[i]);
			l += 2;
		} else {
			sprintf(parsed_mac+l, ":%02x", mac_addr[i]);
			l += 3;
		}
	}
}


void handle_frame(struct nlattr *nl_frame)
{
	uint8_t *frame;
	size_t len;
	int i;
	char macbuf[6*3];
	uint16_t tmp;

	if (!nl_frame)
		printf("NL80211 frame attribute empty\n");

	frame = nla_data(nl_frame);
	len = nla_len(nl_frame);

	if (len < 26) {
		printf("Malformed frame\n");
	
	}


	parse_mac_addr(macbuf, frame + 10);
	printf(" %s -> ", macbuf);
	parse_mac_addr(macbuf, frame + 4);
	printf("%s", macbuf);

	switch (frame[0] & 0xfc) 
        {
	        case 0x10: /* assoc resp */
	        case 0x30: /* reassoc resp */
                case 0x00: /* assoc req */
                        printf("[assoc req]\n");
                        break;
                case 0x20: /* reassoc req */
                case 0x40: /* probe req */
                case 0x50: /* probe resp */
                case 0xb0: /* auth */
                case 0xa0: /* disassoc */
                        printf("[disassoc]\n");
                        break;
                case 0xc0: /* deauth */
                        break;
        }

}

