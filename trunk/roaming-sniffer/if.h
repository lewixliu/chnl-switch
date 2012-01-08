/**
 * @file if.h
 * @brief Main interface for parsing functions.
 * @details All things here are globally accessible.
 *
 * @author Marcin Harasimczuk
 */
#ifndef IF_H
#define IF_H

#include<pcap.h>

/**
 * @brief Parse 802.11 frame.
 * @details Extract frame FC (control field) and check if it is a MGMT frame. Check what type of mgmt it is.
 *
 * @param dump_hdr      Generic header of libpcap.
 * @param packet        Pointer to captured packet.
 */
extern u_int if_ieee802_11_parse(const struct pcap_pkthdr *dump_hdr, const u_char *packet);

/**
 * @brief Parse Radiotap header.
 * @details Parse Radiotap bitmaps (header->it_present) to see which fields are availible. Check flags for 
 * Atheros padding and additional FCS. 
 *
 * @param dump_hdr      Generic header of libpcap.
 * @param packet        Pointer to captured packet.
 */
extern u_int if_radiotap_parse(const struct pcap_pkthdr *dump_hdr, const u_char *packet);

#endif
