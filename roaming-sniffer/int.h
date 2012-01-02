#ifndef INT_H
#define INT_H

#include<pcap.h>

extern u_int ieee802_11_if_print(const struct pcap_pkthdr *, const u_char *);
extern u_int ieee802_11_radio_if_print(const struct pcap_pkthdr *, const u_char *);

#endif
