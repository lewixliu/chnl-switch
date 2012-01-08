/**
 * @file sniffer.c
 * @brief Main sniffer loop initialization.
 * @details Main function: Creating and initializing 
 * capture device; parsing filter file; handling of interrupts;
 * starting main loop.
 *
 * @author Marcin Harasimczuk
 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#include "if.h"

/* Signal compatibility */
#define RETSIGTYPE void
#define RETSIGVAL
/* POSIX compatybility */
#ifndef O_BINARY
#define O_BINARY 0
#endif

static RETSIGTYPE clean(int);
static RETSIGTYPE child_clean(int);

/**
 * @brief Handle packet that was not filtered by external filter expression.
 */
static void handle_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static u_int nofpackets;

/** Capture device */
static pcap_t *pdev;

/**
 * @brief Structure for additional args of sniffer loop.
 * @details Not used right now
 */
struct loop_args 
{
        int arg;
};

/**
 * @brief Function for opening external filter file.
 * @details Function opens an external file and extracts filter string.
 */
char *read_filter(char *filename)
{
        register int i, fd, cc;
        register char *cp;
        struct stat buf;

        fd = open(filename, O_RDONLY|O_BINARY);
        if(fd < 0)
        {
                fprintf(stderr,"cannot open file.\n");
        }

        if(fstat(fd, &buf) < 0)
        {
                fprintf(stderr,"cannot stat.\n");
        }

        cp = malloc((u_int)buf.st_size + 1);
        if(cp == NULL)
        {
                fprintf(stderr,"cannot malloc.\n");
        }

        cc = read(fd, cp, (u_int)buf.st_size);
        if(cc < 0)
        {
                fprintf(stderr,"cannot read.\n");
        }

        if(cc != buf.st_size)
        {
                fprintf(stderr,"short read.\n");
        }

        close(fd);

        cp[cc] = '\0';
        return cp;
}

/**
 * @biref Function printing relative time of packet arrival.
 * @details Used for 802.11 measurments.
 */
void show_time(register const struct timeval *tv)
{
        static unsigned _sec;
        static unsigned _usec;
        static char time[sizeof("00:00:00.000000")];
        int sec;
        int usec;
        
        if(_sec == 0)
        {
                _usec = tv->tv_usec;
                _sec = tv->tv_sec;
        }

        usec = tv->tv_usec - _usec;
        sec = tv->tv_sec - _sec;

        while(usec < 0)
        {
                usec += 1000000;
                sec--;
        }
        
        snprintf(time, sizeof(time), "%02d:%02d:%02d.%06u", 
                        sec / 3600, (sec % 3600) / 60, sec % 60, usec);
        printf("%s ", time);
}

int
main(int argc, char **argv)
{
	register int cnt, i;
	register char *cp, *device;

	struct loop_args largs;
	u_char *pcap_largs;

	char ebuf[PCAP_ERRBUF_SIZE];
        int err;
        long int snapshot_size;

        bpf_u_int32 localnet, netmask;
        struct bpf_program filtercode;

        pcap_handler callback;
        RETSIGTYPE(*oldhandler)(int);

        char *filter;

        /**
         * Hardcoded:
         * Always listen on mon0 monitor interface.
         * With snapshot size 65000.
         * Listen forever.
         * Open filter filenamne "filter".
         */
        snapshot_size = 65000;
	cnt = -1;
	device = "mon0";
        filter = read_filter("filter");

        /* Create capture device */
        pdev = pcap_create(device, ebuf);
        if (pdev == NULL)
                fprintf(stderr, "cannot create capture device: %s\n", ebuf);

        /* Init capture device */
        err = pcap_set_snaplen(pdev, snapshot_size);
        if (err != 0)
                fprintf(stderr, "cannot set snapshot size: %s: %s\n",
                        device, pcap_statustostr(err));

        /* Set promiscus mode */
        err = pcap_set_promisc(pdev, 1);
        if (err != 0)
                fprintf(stderr, "cannot set promiscus mode: %s: %s\n",
                        device, pcap_statustostr(err));

        /* Set timeout */
        err = pcap_set_timeout(pdev, 1000);
        if (err != 0)
                fprintf(stderr, "cannot set timeout: %s: %s\n",
                        device, pcap_statustostr(err));

        /* Activate capture device */
        err = pcap_activate(pdev);
        if (err < 0) 
        {
                /* Activation failed -report */
                cp = pcap_geterr(pdev);
                if (err == PCAP_ERROR)
                        fprintf(stderr, "capture device activate error: %s\n", cp);
                else if ((err == PCAP_ERROR_NO_SUCH_DEVICE ||
                          err == PCAP_ERROR_PERM_DENIED) &&
                         *cp != '\0')
                        fprintf(stderr, "capture device activate error: %s: %s\n(%s)\n", device,
                            pcap_statustostr(err), cp);
                else 
                        fprintf(stderr, "capture device activate error: %s: %s\n", device,
                            pcap_statustostr(err));
        } 
        else if (err > 0) 
        {
                /* Activate success with warning */
                cp = pcap_geterr(pdev);
                if (err == PCAP_WARNING)
                        fprintf(stderr, "capture device activate warning: %s\n", cp);
                else if (err == PCAP_WARNING_PROMISC_NOTSUP &&
                         *cp != '\0')
                        fprintf(stderr, "capture device activate warning: %s: %s\n(%s)\n", device,
                            pcap_statustostr(err), cp);
                else
                        fprintf(stderr, "capture device activate warning: %s: %s\n", device,
                            pcap_statustostr(err));
        }

        /* Check snapshot size after init */
        i = pcap_snapshot(pdev);
        if (snapshot_size < i) 
        {
                fprintf(stderr, "snapshot size raised from %lu to %d\n", snapshot_size, i);
                /* Used when snapshot size is global */
                snapshot_size = i;
        }
        /* Check sniffed network */
        if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) 
        {
                localnet = 0;
                netmask = 0;
                fprintf(stderr, "network lookup: %s\n", ebuf);
        }

        /* Compile filter code */
	if (pcap_compile(pdev, &filtercode, filter, 0, netmask) < 0)
		fprintf(stderr, "filter compilation error: %s", pcap_geterr(pdev));

        /* Set signals for graceful exit */
	sigset(SIGPIPE, clean);
	sigset(SIGTERM, clean);
	sigset(SIGINT, clean);
	sigset(SIGCHLD, child_clean);
	/* Cooperate with nohup(1) */
	if ((oldhandler = sigset(SIGHUP, clean)) != SIG_DFL)
		sigset(SIGHUP, oldhandler);

        /* Set compiled filter */ 
	if (pcap_setfilter(pdev, &filtercode) < 0)
		printf("%s", pcap_geterr(pdev));

        /* Prepare arguments for loop */
        callback = handle_packet;
        pcap_largs = (u_char *)&largs;

	err = pcap_loop(pdev, cnt, callback, pcap_largs);

        if (err == -2) 
        {        
                /* Interrupt. Finish printing */
                putchar('\n');
        }
        (void)fflush(stdout);

	if (err == -1) 
        {
		/*
		 * Error.  Report it.
		 */
		fprintf(stderr, "pcap loop error: %s\n", pcap_geterr(pdev));
	}

	pcap_close(pdev);
	exit(err == -1 ? 1 : 0);
}

/* make a clean exit on interrupts */
static RETSIGTYPE
clean(int signo)
{
	alarm(0);
	pcap_breakloop(pdev);
	exit(0);
}

/* Wait for child to exit */
static RETSIGTYPE
child_clean(int signo)
{
  wait(NULL);
}

static void
handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct loop_args *loop_args;
	u_int hdrlen;

	++nofpackets;
        show_time(&h->ts);
	loop_args = (struct loop_args *)user;

        hdrlen = if_radiotap_parse(h, sp);
        //printf("\n");
}
