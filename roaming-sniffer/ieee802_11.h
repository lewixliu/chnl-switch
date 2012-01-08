/**
 * @file ieee802_11.h
 * @brief IEEE802.11 and Radiotap constants and macros.
 * @details Constants describing 802.11 and Radiotap headers. 
 * Macros for extraction and aligning of binary 
 * little-endian data.
 *
 * @author Marcin Harasimczuk
 */

#ifndef IEEE802_11_H
#define IEEE802_11_H

#include <stdio.h>
#include <pcap.h>
#include <string.h>

/**
 * @def	IEEE802_11_FC_LEN	
 * Length of the frame control field.
 *
 * @def	IEEE802_11_DUR_LEN
 * Duration/ID field length.
 *
 * @def	IEEE802_11_DA_LEN
 * Destination address length.
 *
 * @def	IEEE802_11_SA_LEN
 * Source address length.
 *
 * @def	IEEE802_11_BSSID_LEN
 * Basic service set length.
 *
 * @def	IEEE802_11_RA_LEN	
 * Receiver address length.
 *
 * @def	IEEE802_11_TA_LEN
 * Trasmitter address length.
 *
 * @def	IEEE802_11_SEQ_LEN	
 * Sequence number length.
 *
 * @def	IEEE802_11_CTL_LEN	
 * Sequence control length.
 *
 * @def	IEEE802_11_IV_LEN
 * Initialization vector (WEP) length.
 *
 * @def	IEEE802_11_KID_LEN
 *
 * @def	IEEE802_11_FCS_LEN
 * Frame check sequence length.
 *
 * @def	IEEE802_11_TSTAMP_LEN
 * Timestamp length. Beacon component.
 *
 * @def	IEEE802_11_BCNINT_LEN
 * Beacon component.
 *
 * @def	IEEE802_11_CAPINFO_LEN
 * Beacon component.
 *
 * @def	IEEE802_11_LISTENINT_LEN
 * Beacon component.
 *
 * @def	IEEE802_11_AID_LEN
 * Beacon component.
 *
 * @def	IEEE802_11_STATUS_LEN
 * Status code length.
 *
 * @def	IEEE802_11_REASON_LEN
 * Reason code length.
 *
 * @def	IEEE802_11_AP_LEN	
 * Previous AP in reasociation frame.
 */

/* Lengths of frame components. */
/* 802.11 header components. */
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
/* Frame check sequence. */
#define	IEEE802_11_FCS_LEN		4
/* Beacon components. */
#define	IEEE802_11_TSTAMP_LEN		8
#define	IEEE802_11_BCNINT_LEN		2
#define	IEEE802_11_CAPINFO_LEN		2
#define	IEEE802_11_LISTENINT_LEN	2
#define	IEEE802_11_AID_LEN		2
#define	IEEE802_11_STATUS_LEN		2
#define	IEEE802_11_REASON_LEN		2
/* Previous AP in reassocation frame */
#define	IEEE802_11_AP_LEN		6

/* IEEE802.11 frame types */
/** Management frame */
#define	T_MGMT 0x0      
/** Control frame */
#define	T_CTRL 0x1      
/** Data frame */
#define	T_DATA 0x2      
/** Reserved frames */
#define	T_RESV 0x3      

/* IEEE802-11 frame subtypes */
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


/* IEEE80211_RADIOTAP_FLAGS */
/** sent/received during Contention Free Period */
#define	IEEE80211_RADIOTAP_F_CFP	0x01
/** sent/received with short preamble */
#define	IEEE80211_RADIOTAP_F_SHORTPRE	0x02
/** sent/received with WEP enc. */
#define	IEEE80211_RADIOTAP_F_WEP	0x04	
/** sent/received with fragmentation */
#define	IEEE80211_RADIOTAP_F_FRAG	0x08
/** FCS included */
#define	IEEE80211_RADIOTAP_F_FCS	0x10	
/** Frame has padding between 802.11 header and payload to 32-bit boundary */
#define	IEEE80211_RADIOTAP_F_DATAPAD	0x20
/** Failed FCS check */
#define	IEEE80211_RADIOTAP_F_BADFCS	0x40
/** HT short GI */
#define	IEEE80211_RADIOTAP_F_SHORTGI	0x80

/*
 * Macros
 */

/** Extract frame type */
#define	EXTRACT_TYPE(fc)		(((fc) >> 2) & 0x3)
/** Extract frame subtype */
#define	EXTRACT_SUBTYPE(fc)		(((fc) >> 4) & 0xF)

/** Return integer according to bit position in 32 bit word */
#define	BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define	BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define	BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define	BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define	BITNO_2(x) (((x) & 2) ? 1 : 0)

#define	BIT(n)	(1U << n)

/** Check if Radiotap header bitmap is extended with another one */
#define	IS_EXTENDED(__p)	\
	    (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

/*
 * Macros to extract possibly-unaligned little-endian integral values.
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

/** 
 * @brief Structure representing the Radiotap header. 
 */
struct ieee80211_radiotap_header {
	/** 
         * Version 0. Only increases
	 * for drastic changes,
         * introduction of compatible
         * new fields does not count.
         */
	u_int8_t	it_version;	
        /**
         * Padding.
         */
        u_int8_t	it_pad;
        /** 
         * Length of the whole
         * header in bytes, including
         * it_version, it_pad,
         * it_len, and data fields.
         */
	u_int16_t       it_len;  
        /** 
         * A bitmap telling which
         * fields are present. Set bit 31
         * (0x80000000) to extend the
         * bitmap by another 32 bits.
         * Additional extensions are made
         * by setting bit 31.
         */
        u_int32_t       it_present;    
};

/**
 * @brief Radiotap field types.
 */
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

/** 
 *      @brief Structure containing current state of radiotap fields.
 *      @details This structure represents radiotap data area and is used
 *      for unpacking data fields according to bitmap retrieved from header.
 */
struct unpacker {
        /** Pointer to the beginning of radiotap data fields area of packet. */
	u_int8_t					*u_buf;
        /** Pointer to the next packet area that was not yet extracted */
	u_int8_t					*u_next;
        /** Length of the radiotap data fields area */
	size_t						 u_len;
};


/** @brief Initialize unpacker structure */
int unpack_init(struct unpacker *un, u_int8_t *buf, size_t buflen);
/** @brief Unpack unsigned int of 64 bits */
int unpack_uint64(struct unpacker *un, u_int64_t *u);
/** @brief Unpack unsigned int of 32 bits */
int unpack_uint32(struct unpacker *un, u_int32_t *u);
/** @brief Unpack unsigned int of 16 bits */
int unpack_uint16(struct unpacker *un, u_int16_t *u);
/** @brief Unpack unsigned int of 8 bits */
int unpack_uint8(struct unpacker *un, u_int8_t *u);

#endif
