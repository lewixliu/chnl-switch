#include<stdio.h>
#include "usr_iface.h"

int open_exp( FILE * exp_fp )
{
        int stdin_bytes_read;
        int stdin_nbytes = 100;
        char *stdin_string_read;

        /* Get experiment filename */
        puts("Enter experiment data file name.");
        stdin_string_read = (char *) malloc(stdin_nbytes + 1);
        stdin_bytes_read = getline(&stdin_string_read, &stdin_nbytes, stdin);

        if (stdin_bytes_read == -1)
        {
                puts ("Input error.");
                exp_fp = NULL;
                return -1;
        }

        /* Open or create experiment file */
        exp_fp = fopen(stdin_string_read, "a");
        return 0;
}

void close_exp( FILE *exp_fp )
{
        fclose(exp_fp);
}

int init_roaming_data( roaming_data * rd )
{
        int stdin_bytes_read;
        int stdin_nbytes = 100;
        
        rd = (roaming_data *) malloc(sizeof(roaming_data));
        if(!rd)
        {
                return -1;
        }

        puts("Enter MAC address of Access Point #1.");
        rd->ap_1_mac = (char *) malloc(stdin_nbytes + 1);
        stdin_bytes_read = getline(&rd->ap_1_mac, &stdin_nbytes, stdin);

        if (stdin_bytes_read == -1)
        {
                puts ("Input error.");
                return -2;
        }
        stdin_bytes_read = 0;

        puts("Enter MAC address of Access Point #2.");
        rd->ap_2_mac = (char *) malloc(stdin_nbytes + 1);
        stdin_bytes_read = getline(&rd->ap_2_mac, &stdin_nbytes, stdin);

        if (stdin_bytes_read == -1)
        {
                puts ("Input error.");
                return -2;
        }
        stdin_bytes_read = 0;

        puts("Enter MAC address of Client Station.");
        rd->client_mac = (char *) malloc(stdin_nbytes + 1);
        stdin_bytes_read = getline(&rd->client_mac, &stdin_nbytes, stdin);

        if (stdin_bytes_read == -1)
        {
                puts ("Input error.");
                return -2;
        }

        return 0;
}

void clean_roaming_data( roaming_data * rd )
{
        free(rd->ap_1_mac);
        free(rd->ap_2_mac);
        free(rd->client_mac);
        free(rd);
}

