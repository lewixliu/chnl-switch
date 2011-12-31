
#ifndef USR_IFACE_H
#define USR_IFACE_H

struct _roaming_data 
{
        char *ap_1_mac;
        char *ap_2_mac;
        char *client_mac;
}

typedef _roaming_data roaming_data;

void open_exp( FILE *exp_fp );
void close_exp( FILE *exp_fp );
int init_roaming_data( roaming_data * rd );
void clean_roaming_data( roaming_data * rd );

#endif
