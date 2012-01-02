#include "int.h"


/* Lengths of 802.11 header components. */
#define	IEEE802_11_FC_LEN		2
#define	IEEE802_11_DUR_LEN		2
#define	IEEE802_11_DA_LEN		6
#define	IEEE802_11_SA_LEN		6
#define	IEEE802_11_BSSID_LEN		6
#define	IEEE802_11_RA_LEN		6
#define	IEEE802_11_TA_LEN		6
#define	IEEE802_11_SEQ_LEN		2
#define	IEEE802_11_CTL_LEN		2
#define	IEEE802_11_IV_LEN		3
#define	IEEE802_11_KID_LEN		1

/* Frame check sequence length. */
#define	IEEE802_11_FCS_LEN		4

/* Lengths of beacon components. */
#define	IEEE802_11_TSTAMP_LEN		8
#define	IEEE802_11_BCNINT_LEN		2
#define	IEEE802_11_CAPINFO_LEN		2
#define	IEEE802_11_LISTENINT_LEN	2

#define	IEEE802_11_AID_LEN		2
#define	IEEE802_11_STATUS_LEN		2
#define	IEEE802_11_REASON_LEN		2

/* Length of previous AP in reassocation frame */
#define	IEEE802_11_AP_LEN		6

#define	T_MGMT 0x0  /* management */
#define	T_CTRL 0x1  /* control */
#define	T_DATA 0x2 /* data */
#define	T_RESV 0x3  /* reserved */

#define	ST_ASSOC_REQUEST   	0x0
#define	ST_ASSOC_RESPONSE 	0x1
#define	ST_REASSOC_REQUEST   	0x2
#define	ST_REASSOC_RESPONSE  	0x3
#define	ST_PROBE_REQUEST   	0x4
#define	ST_PROBE_RESPONSE   	0x5
/* RESERVED 			0x6  */
/* RESERVED 			0x7  */
#define	ST_BEACON   		0x8
#define	ST_ATIM			0x9
#define	ST_DISASSOC		0xA
#define	ST_AUTH			0xB
#define	ST_DEAUTH		0xC
#define	ST_ACTION		0xD
/* RESERVED 			0xE  */
/* RESERVED 			0xF  */

#define	FC_TYPE(fc)		(((fc) >> 2) & 0x3)
#define	FC_SUBTYPE(fc)		(((fc) >> 4) & 0xF)



/*
 * Macros to extract possibly-unaligned little-endian integral values.
 * XXX - do loads on little-endian machines that support unaligned loads?
 */
#define EXTRACT_LE_8BITS(p) (*(p))
#define EXTRACT_LE_16BITS(p) \
	((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
		     (u_int16_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_32BITS(p) \
	((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 3) << 24 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_24BITS(p) \
	((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
		     (u_int32_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_64BITS(p) \
	((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 7) << 56 | \
		     (u_int64_t)*((const u_int8_t *)(p) + 6) << 48 | \
		     (u_int64_t)*((const u_int8_t *)(p) + 5) << 40 | \
		     (u_int64_t)*((const u_int8_t *)(p) + 4) << 32 | \
	             (u_int64_t)*((const u_int8_t *)(p) + 3) << 24 | \
		     (u_int64_t)*((const u_int8_t *)(p) + 2) << 16 | \
		     (u_int64_t)*((const u_int8_t *)(p) + 1) << 8 | \
		     (u_int64_t)*((const u_int8_t *)(p) + 0)))

#define cpack_int8(__s, __p)	cpack_uint8((__s),  (u_int8_t*)(__p))
#define cpack_int16(__s, __p)	cpack_uint16((__s), (u_int16_t*)(__p))
#define cpack_int32(__s, __p)	cpack_uint32((__s), (u_int32_t*)(__p))
#define cpack_int64(__s, __p)	cpack_uint64((__s), (u_int64_t*)(__p))

/* channel attributes */
#define	IEEE80211_CHAN_TURBO	0x00010	/* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x00020	/* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x00040	/* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x00080	/* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x00100	/* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x00200	/* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x00400	/* Dynamic CCK-OFDM channel */
#define	IEEE80211_CHAN_GFSK	0x00800	/* GFSK channel (FHSS PHY) */
#define	IEEE80211_CHAN_GSM	0x01000	/* 900 MHz spectrum channel */
#define	IEEE80211_CHAN_STURBO	0x02000	/* 11a static turbo channel only */
#define	IEEE80211_CHAN_HALF	0x04000	/* Half rate channel */
#define	IEEE80211_CHAN_QUARTER	0x08000	/* Quarter rate channel */
#define	IEEE80211_CHAN_HT20	0x10000	/* HT 20 channel */
#define	IEEE80211_CHAN_HT40U	0x20000	/* HT 40 channel w/ ext above */
#define	IEEE80211_CHAN_HT40D	0x40000	/* HT 40 channel w/ ext below */

/* For IEEE80211_RADIOTAP_FLAGS */
#define	IEEE80211_RADIOTAP_F_CFP	0x01	/* sent/received
						 * during CFP
						 */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02	/* sent/received
						 * with short
						 * preamble
						 */
#define	IEEE80211_RADIOTAP_F_WEP	0x04	/* sent/received
						 * with WEP encryption
						 */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08	/* sent/received
						 * with fragmentation
						 */
#define	IEEE80211_RADIOTAP_F_FCS	0x10	/* frame includes FCS */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20	/* frame has padding between
						 * 802.11 header and payload
						 * (to 32-bit boundary)
						 */
#define	IEEE80211_RADIOTAP_F_BADFCS	0x40	/* does not pass FCS check */
#define	IEEE80211_RADIOTAP_F_SHORTGI	0x80	/* HT short GI */


#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

#define	IS_CHAN_FHSS(flags) \
	((flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define	IS_CHAN_A(flags) \
	((flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IS_CHAN_B(flags) \
	((flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IS_CHAN_PUREG(flags) \
	((flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IS_CHAN_G(flags) \
	((flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IS_CHAN_ANYG(flags) \
	(IS_CHAN_PUREG(flags) || IS_CHAN_G(flags))


struct cpack_state {
	u_int8_t					*c_buf;
	u_int8_t					*c_next;
	size_t						 c_len;
};

struct ieee80211_radiotap_header {
	u_int8_t	it_version;	/* Version 0. Only increases
					 * for drastic changes,
					 * introduction of compatible
					 * new fields does not count.
					 */
	u_int8_t	it_pad;
	u_int16_t       it_len;         /* length of the whole
					 * header in bytes, including
					 * it_version, it_pad,
					 * it_len, and data fields.
					 */
	u_int32_t       it_present;     /* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
};

enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	/* NB: gap for netbsd definitions */
	IEEE80211_RADIOTAP_XCHANNEL = 18,
	IEEE80211_RADIOTAP_EXT = 31
};



/* cpak */
static u_int8_t *
cpack_next_boundary(u_int8_t *buf, u_int8_t *p, size_t alignment)
{
	size_t misalignment = (size_t)(p - buf) % alignment;

	if (misalignment == 0)
		return p;

	return p + (alignment - misalignment);
}

/* Advance to the next wordsize boundary. Return NULL if fewer than
 * wordsize bytes remain in the buffer after the boundary.  Otherwise,
 * return a pointer to the boundary.
 */
static u_int8_t *
cpack_align_and_reserve(struct cpack_state *cs, size_t wordsize)
{
	u_int8_t *next;

	/* Ensure alignment. */
	next = cpack_next_boundary(cs->c_buf, cs->c_next, wordsize);

	/* Too little space for wordsize bytes? */
	if (next - cs->c_buf + wordsize > cs->c_len)
		return NULL;

	return next;
}

int
cpack_init(struct cpack_state *cs, u_int8_t *buf, size_t buflen)
{
	memset(cs, 0, sizeof(*cs));

	cs->c_buf = buf;
	cs->c_len = buflen;
	cs->c_next = cs->c_buf;

	return 0;
}

/* Unpack a 64-bit unsigned integer. */
int
cpack_uint64(struct cpack_state *cs, u_int64_t *u)
{
	u_int8_t *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_64BITS(next);

	/* Move pointer past the u_int64_t. */
	cs->c_next = next + sizeof(*u);
	return 0;
}

/* Unpack a 32-bit unsigned integer. */
int
cpack_uint32(struct cpack_state *cs, u_int32_t *u)
{
	u_int8_t *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_32BITS(next);

	/* Move pointer past the u_int32_t. */
	cs->c_next = next + sizeof(*u);
	return 0;
}

/* Unpack a 16-bit unsigned integer. */
int
cpack_uint16(struct cpack_state *cs, u_int16_t *u)
{
	u_int8_t *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_16BITS(next);

	/* Move pointer past the u_int16_t. */
	cs->c_next = next + sizeof(*u);
	return 0;
}

/* Unpack an 8-bit unsigned integer. */
int
cpack_uint8(struct cpack_state *cs, u_int8_t *u)
{
	/* No space left? */
	if ((size_t)(cs->c_next - cs->c_buf) >= cs->c_len)
		return -1;

	*u = *cs->c_next;

	/* Move pointer past the u_int8_t. */
	cs->c_next++;
	return 0;
}

static void
print_chaninfo(int freq, int flags)
{
	printf("%u MHz", freq);
	if (IS_CHAN_FHSS(flags))
		printf(" FHSS");
	if (IS_CHAN_A(flags)) {
		if (flags & IEEE80211_CHAN_HALF)
			printf(" 11a/10Mhz");
		else if (flags & IEEE80211_CHAN_QUARTER)
			printf(" 11a/5Mhz");
		else
			printf(" 11a");
	}
	if (IS_CHAN_ANYG(flags)) {
		if (flags & IEEE80211_CHAN_HALF)
			printf(" 11g/10Mhz");
		else if (flags & IEEE80211_CHAN_QUARTER)
			printf(" 11g/5Mhz");
		else
			printf(" 11g");
	} else if (IS_CHAN_B(flags))
		printf(" 11b");
	if (flags & IEEE80211_CHAN_TURBO)
		printf(" Turbo");
	if (flags & IEEE80211_CHAN_HT20)
		printf(" ht/20");
	else if (flags & IEEE80211_CHAN_HT40D)
		printf(" ht/40-");
	else if (flags & IEEE80211_CHAN_HT40U)
		printf(" ht/40+");
	printf(" ");
}



static int
print_radiotap_field(struct cpack_state *s, u_int32_t bit, u_int8_t *flags)
{
	union {
		int8_t		i8;
		u_int8_t	u8;
		int16_t		i16;
		u_int16_t	u16;
		u_int32_t	u32;
		u_int64_t	u64;
	} u, u2, u3, u4;
	int rc;

	switch (bit) {
	case IEEE80211_RADIOTAP_FLAGS:
		rc = cpack_uint8(s, &u.u8);
		*flags = u.u8;
		break;
	case IEEE80211_RADIOTAP_RATE:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_ANTENNA:
		rc = cpack_uint8(s, &u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		rc = cpack_int8(s, &u.i8);
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		rc = cpack_uint16(s, &u.u16);
		if (rc != 0)
			break;
		rc = cpack_uint16(s, &u2.u16);
		break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
		rc = cpack_uint16(s, &u.u16);
		break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
		rc = cpack_uint8(s, &u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
		rc = cpack_int8(s, &u.i8);
		break;
	case IEEE80211_RADIOTAP_TSFT:
		rc = cpack_uint64(s, &u.u64);
		break;
	case IEEE80211_RADIOTAP_XCHANNEL:
		rc = cpack_uint32(s, &u.u32);
		if (rc != 0)
			break;
		rc = cpack_uint16(s, &u2.u16);
		if (rc != 0)
			break;
		rc = cpack_uint8(s, &u3.u8);
		if (rc != 0)
			break;
		rc = cpack_uint8(s, &u4.u8);
		break;
	default:
		/* this bit indicates a field whose
		 * size we do not know, so we cannot
		 * proceed.  Just print the bit number.
		 */
		printf("[bit %u] ", bit);
		return -1;
	}

	if (rc != 0) {
		printf("[|802.11]");
		return rc;
	}

	switch (bit) {
	case IEEE80211_RADIOTAP_CHANNEL:
		print_chaninfo(u.u16, u2.u16);
		break;
	case IEEE80211_RADIOTAP_FHSS:
		printf("fhset %d fhpat %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		printf("%ddB signal ", u.i8);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		printf("%ddB noise ", u.i8);
		break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
		printf("%ddB signal ", u.u8);
		break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
		printf("%ddB noise ", u.u8);
		break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
		printf("%u sq ", u.u16);
		break;
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
		printf("%d tx power ", -(int)u.u16);
		break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
		printf("%ddB tx power ", -(int)u.u8);
		break;
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
		printf("%ddBm tx power ", u.i8);
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		if (u.u8 & IEEE80211_RADIOTAP_F_CFP)
			printf("cfp ");
		if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE)
			printf("short preamble ");
		if (u.u8 & IEEE80211_RADIOTAP_F_WEP)
			printf("wep ");
		if (u.u8 & IEEE80211_RADIOTAP_F_FRAG)
			printf("fragmented ");
		if (u.u8 & IEEE80211_RADIOTAP_F_BADFCS)
			printf("bad-fcs ");
		break;
	case IEEE80211_RADIOTAP_ANTENNA:
		printf("antenna %d ", u.u8);
		break;
	case IEEE80211_RADIOTAP_XCHANNEL:
		print_chaninfo(u2.u16, u.u32);
		break;
	}
	return 0;
}

static u_int
ieee802_11_print(const u_char *p, u_int length, u_int orig_caplen, int pad,
    u_int fcslen)
{
	u_int16_t fc;
	u_int caplen, hdrlen;
	const u_int8_t *src, *dst;

	caplen = orig_caplen;
	/* Remove FCS, if present */
	if (length < fcslen) {
		printf("[|802.11]");
		return caplen;
	}
	length -= fcslen;
	if (caplen > length) {
		/* Amount of FCS in actual packet data, if any */
		fcslen = caplen - length;
		caplen -= fcslen;
		/*snapend -= fcslen;*/
	}

	if (caplen < IEEE802_11_FC_LEN) {
		printf("[|802.11]");
		return orig_caplen;
	}

	fc = EXTRACT_LE_16BITS(p);

        if(FC_TYPE(fc) == T_MGMT)
        {
                switch (FC_SUBTYPE(fc)) {
                case ST_ASSOC_REQUEST:
                        printf("Assoc Request");
                        /*return handle_assoc_request(p, length);*/
                        break;
                case ST_ASSOC_RESPONSE:
                        printf("Assoc Response");
                        /*return handle_assoc_response(p, length);*/
                        break;
                case ST_REASSOC_REQUEST:
                        printf("ReAssoc Request");
                        /*return handle_reassoc_request(p, length);*/
                        break;
                case ST_REASSOC_RESPONSE:
                        printf("ReAssoc Response");
                        /*return handle_reassoc_response(p, length);*/
                        break;
                case ST_PROBE_REQUEST:
                        printf("Probe Request");
                        /*return handle_probe_request(p, length);*/
                        break;
                case ST_PROBE_RESPONSE:
                        printf("Probe Response");
                        /*return handle_probe_response(p, length);*/
                        break;
                case ST_BEACON:
                        printf("Beacon");
                        /*return handle_beacon(p, length);*/
                        break;
                case ST_ATIM:
                        printf("ATIM");
                        /*return handle_atim();*/
                        break;
                case ST_DISASSOC:
                        printf("Disassociation");
                        /*return handle_disassoc(p, length);*/
                        break;
                case ST_AUTH:
                        printf("Authentication");
                        /*
                        if (!TTEST2(*p, 3))
                                return 0;
                        if ((p[0] == 0 ) && (p[1] == 0) && (p[2] == 0)) {
                                printf("Authentication (Shared-Key)-3 ");
                                return wep_print(p);
                        }
                        return handle_auth(p, length);
                        */
                        break;
                case ST_DEAUTH:
                        printf("DeAuthentication");
                        /*return handle_deauth(pmh, p, length);*/
                        break;
                case ST_ACTION:
                        printf("Action");
                        /*return handle_action(pmh, p, length);*/
                        break;
                default:
                        printf("Unhandled Management subtype(%x)",
                            FC_SUBTYPE(fc));
                        break;
                }
        }
        else
        {
                printf(" Not MGMT ");
        }


	return 0;
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the 802.11 header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
u_int
ieee802_11_if_print(const struct pcap_pkthdr *h, const u_char *p)
{
	return ieee802_11_print(p, h->len, h->caplen, 0, 0);
}


static u_int
ieee802_11_radio_print(const u_char *p, u_int length, u_int caplen)
{
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)
#define	BIT(n)	(1U << n)
#define	IS_EXTENDED(__p)	\
	    (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

	struct cpack_state cpacker;
	struct ieee80211_radiotap_header *hdr;
	u_int32_t present, next_present;
	u_int32_t *presentp, *last_presentp;
	enum ieee80211_radiotap_type bit;
	int bit0;
	const u_char *iter;
	u_int len;
	u_int8_t flags;
	int pad;
	u_int fcslen;

	if (caplen < sizeof(*hdr)) {
		printf("[|802.11]");
		return caplen;
	}

	hdr = (struct ieee80211_radiotap_header *)p;

	len = EXTRACT_LE_16BITS(&hdr->it_len);

	if (caplen < len) {
		printf("[|802.11]");
		return caplen;
	}
	for (last_presentp = &hdr->it_present;
	     IS_EXTENDED(last_presentp) &&
	     (u_char*)(last_presentp + 1) <= p + len;
	     last_presentp++);

	/* are there more bitmap extensions than bytes in header? */
	if (IS_EXTENDED(last_presentp)) {
		printf("[|802.11]");
		return caplen;
	}

	iter = (u_char*)(last_presentp + 1);

	if (cpack_init(&cpacker, (u_int8_t*)iter, len - (iter - p)) != 0) {
		/* XXX */
		printf("[|802.11]");
		return caplen;
	}

	/* Assume no flags */
	flags = 0;
	/* Assume no Atheros padding between 802.11 header and body */
	pad = 0;
	/* Assume no FCS at end of frame */
	fcslen = 0;
	for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
	     presentp++, bit0 += 32) {
		for (present = EXTRACT_LE_32BITS(presentp); present;
		     present = next_present) {
			/* clear the least significant bit that is set */
			next_present = present & (present - 1);

			/* extract the least significant bit that is set */
			bit = (enum ieee80211_radiotap_type)
			    (bit0 + BITNO_32(present ^ next_present));

			if (print_radiotap_field(&cpacker, bit, &flags) != 0)
				goto out;
		}
	}

	if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
		pad = 1;	/* Atheros padding */
	if (flags & IEEE80211_RADIOTAP_F_FCS)
		fcslen = 4;	/* FCS at end of packet */
out:
	return len + ieee802_11_print(p + len, length - len, caplen - len, pad,
	    fcslen);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}


/*
 * For DLT_IEEE802_11_RADIO; like DLT_IEEE802_11, but with an extra
 * header, containing information such as radio information.
 */
u_int
ieee802_11_radio_if_print(const struct pcap_pkthdr *h, const u_char *p)
{
	return ieee802_11_radio_print(p, h->len, h->caplen);
}

