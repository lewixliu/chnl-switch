/**
 * @file ieee802_11.c
 * @brief Functions for parsing Radiotap and 802.11 headers and fields.
 * @details Basically just 2 interface functions based on tcpdump. We are
 * listening on a monitor interface so we need to parse Radiotap header. After
 * Radiotap header we can parse the 802.11 frame.
 *
 * @author Marcin Harasimczuk
 */


#include "ieee802_11.h"
#include "if.h"

static void
handle_freq(int freq, int flags)
{
	printf("%u MHz", freq);
	printf(" ");
}

static int
handle_radiotap_field(struct unpacker *s, u_int32_t field, u_int8_t *flags)
{
	int error;

        u_int8_t radiotap_flags;
        u_int8_t chan_num;
        u_int8_t max_tr_pow;
        u_int16_t chan_frequency;
        u_int16_t chan_prop;
        u_int32_t xchan_prop;
        
	switch (field) 
        {
        /* Return flags to check padding and FCS */
	case IEEE80211_RADIOTAP_FLAGS:
		error = unpack_uint8(s, &radiotap_flags);
		*flags = radiotap_flags;
		break;
        /* Deprecated in favor of XCHANNEL */
	case IEEE80211_RADIOTAP_CHANNEL:
                /* Center frequency */
		error = unpack_uint16(s, &chan_frequency);
		if (error != 0)
			break;
                /* Channel properities */
		error = unpack_uint16(s, &chan_prop);
		break;
	case IEEE80211_RADIOTAP_XCHANNEL:
                /* Channel properities */
		error = unpack_uint32(s, &xchan_prop);
		if (error != 0)
			break;
                /* Center frequency */
		error = unpack_uint16(s, &chan_frequency);
		if (error != 0)
			break;
                /* Channel number */
		error = unpack_uint8(s, &chan_num);
		if (error != 0)
			break;
                /* Max transmit power */
		error = unpack_uint8(s, &max_tr_pow);
		break;
	default:
		return -1;
        }

	if (error != 0) 
        {
		return error;
	}

	return 0;
}

static u_int
ieee802_11_parse(const u_char *packet, u_int length, u_int orig_caplen, int padding, u_int fcslen)
{
	u_int16_t fc;
        struct mgmt_hdr *mh = (struct mgmt_hdr *) packet;

	fc = EXTRACT_LE_16BITS(packet);

        if(EXTRACT_TYPE(fc) == T_MGMT)
        {
                /* MGMT subtype */
                switch (EXTRACT_SUBTYPE(fc)) {
                case ST_ASSOC_REQUEST:
                        printf("Assoc Request ");
                        break;
                case ST_ASSOC_RESPONSE:
                        printf("Assoc Response ");
                        break;
                case ST_REASSOC_REQUEST:
                        printf("ReAssoc Request ");
                        break;
                case ST_REASSOC_RESPONSE:
                        printf("ReAssoc Response ");
                        break;
                case ST_PROBE_REQUEST:
                        if(ioctl(skfd, SIOCSIWFREQ, &wrq) < 0)
                        {
                                fprintf(stderr, "failed to switch channel\n");
                                return(-1);
                        }                                                   
                        printf("Probe Request - channel switched ");
                        break;
                case ST_PROBE_RESPONSE:
                        printf("Probe Response ");
                        break;
                case ST_BEACON:
                        printf("Beacon ");
                        break;
                case ST_ATIM:
                        printf("ATIM ");
                        break;
                case ST_DISASSOC:
                        if(ioctl(skfd, SIOCSIWFREQ, &wrq) < 0)
                        {
                                fprintf(stderr, "failed to switch channel\n");
                                return(-1);
                        }                                                   
                        printf("Disassociation - channel switched ");
                        break;
                case ST_AUTH:
                        printf("Authentication ");
                        break;
                case ST_DEAUTH:
                        printf("DeAuthentication ");
                        break;
                case ST_ACTION:
                        printf("Action ");
                        break;
                default:
                        printf("Unhandled Management subtype(%x) ",
                                EXTRACT_SUBTYPE(fc));
                        break;
                }

                /* Address */
                printf("SA: %x:%x:%x:%x:%x:%x ", mh->sa[0], mh->sa[1], 
                                mh->sa[2], mh->sa[3], mh->sa[4], mh->sa[5]);
        }
        else
        {
                printf(" Not MGMT ");
        }


	return 0;
}

/* Interface */
u_int
if_ieee802_11_parse(const struct pcap_pkthdr *dump_hdr, const u_char *packet)
{
	return ieee802_11_parse(packet, dump_hdr->len, dump_hdr->caplen, 0, 0);
}


static u_int
radiotap_parse(const u_char *packet, u_int length, u_int caplen)
{
	struct unpacker up;
	struct ieee80211_radiotap_header *hdr;
	enum ieee80211_radiotap_type bit;
	int bit0;
	const u_char *fields;
	u_int len;
	u_int8_t flags;
	int pad;
	u_int fcslen;
        
	u_int32_t bitmap, next_bitmap;
	u_int32_t *bitmapp, *last_bitmapp;

        //printf("%s\n", rd.ap_1_mac);

        /* Length of captured data is less than size of radiotap header */
	if (caplen < sizeof(*hdr)) {
		printf("[|802.11]");
		return caplen;
	}

        /* Extract radiotap header from captured packet */
	hdr = (struct ieee80211_radiotap_header *)packet;

        /* 
         * Extract length of radiotap part form radiotap header
         * (version, padding, length, bitmaps, data fields)
         */
	len = EXTRACT_LE_16BITS(&hdr->it_len);

        /* 
         * Captured packet is smaller then overall packet size
         * (should not happen with large enough snapshot size)
         */
	if (caplen < len) {
		printf("[|802.11]");
		return caplen;
	}
        /* 
         * Extract the end of radiotap header bitmap. Bitmap
         * says which radiotap fields are present and can be
         * extended. Keep track of overall radiotap size 
         * (captured packet beginning + length of radiotap).
         */
	for (last_bitmapp = &hdr->it_present;
	     IS_EXTENDED(last_bitmapp) &&
	     (u_char*)(last_bitmapp + 1) <= packet + len;
	     last_bitmapp++);

	/* There are more bitmap extensions than bytes in header */
	if (IS_EXTENDED(last_bitmapp)) {
		printf("[|802.11]");
		return caplen;
	}

        /* 
         * Pointer to one 32 bit part after end of bitmaps. 
         * (Beginning of radiotap data fields).
         * 
         */
	fields = (u_char*)(last_bitmapp + 1);

        /* 
         * Initialize structure used of unpacking radiotap fields
         * with beginning of data fields part of radiotap and size
         * of this part.
         */
	if (unpack_init(&up, (u_int8_t*)fields, len - (fields - packet)) != 0) {
		printf("[|802.11]");
		return caplen;
	}

        /* Parsing of radiotap data fields */

	/* No radiotap flags */
	flags = 0;
	/* No Atheros padding between 802.11 header and body */
	pad = 0;
        /* No FCS at end of frame */
	fcslen = 0;

        /* 
         * Iterate through bitmaps. For each bitmap clear bits starting from
         * least significant. For each bit count which of 32 bits it is (what
         * radiotap type it corresponds to).
         */
	for (bit0 = 0, bitmapp = &hdr->it_present; bitmapp <= last_bitmapp;
	     bitmapp++, bit0 += 32) {
		for (bitmap = EXTRACT_LE_32BITS(bitmapp); bitmap;
		     bitmap = next_bitmap) {

			/* Unset least significant bit in bitmap bitmap. */
			next_bitmap = bitmap & (bitmap - 1);

		        /* 
                         * Extract only least significant bit and count which bit
                         * it is. Add bitmap bits for another bitmaps.
                         */
			bit = (enum ieee80211_radiotap_type)
			    (bit0 + BITNO_32(bitmap ^ next_bitmap));

                        /* Handle the radiotap type found */
		
                        if (handle_radiotap_field(&up, bit, &flags) != 0)
				goto out;
		}
	}
        
        /* Modify padding and FCS according to radiotap flags */
	if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
		pad = 1;	
	if (flags & IEEE80211_RADIOTAP_F_FCS)
		fcslen = 4;
out:
        /* 
         * IEEE802.11 frame starts after radiotap so add length. Reduce the size of the frame
         * by radiotap part. Add padding and FCS.
         */
	return len + ieee802_11_parse(packet + len, length - len, caplen - len, pad,
	    fcslen);
}

/* Interface */
u_int
if_radiotap_parse(const struct pcap_pkthdr *dump_hdr, const u_char *packet)
{
	return radiotap_parse(packet, dump_hdr->len, dump_hdr->caplen);
}

