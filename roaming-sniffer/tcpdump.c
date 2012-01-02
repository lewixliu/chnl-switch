/*#include <tcpdump-stdinc.h>*/

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

#include "int.h"
/*
#include "netdissect.h"
#include "interface.h"
#include "addrtoname.h"
#include "machdep.h"
#include "setsignal.h"
#include "gmt2local.h"
#include "pcap-missing.h"
*/

#define RETSIGTYPE void
#define RETSIGVAL

/*
netdissect_options Gndo;
netdissect_options *gndo = &Gndo;
*/
int32_t thiszone;		/* seconds offset from gmt to local time */

char *program_name;

/* Forwards */
static RETSIGTYPE cleanup(int);
static RETSIGTYPE child_cleanup(int);

static void print_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static u_int packets_captured;

typedef u_int (*if_printer)(const struct pcap_pkthdr *, const u_char *);
static pcap_t *pd;

struct print_info {
        if_printer printer;
};

int
main(int argc, char **argv)
{
	register int cnt, i;
	bpf_u_int32 localnet, netmask;
	register char *cp, *device;
	pcap_handler callback;
	struct bpf_program fcode;
	RETSIGTYPE (*oldhandler)(int);
	struct print_info printinfo;
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];
	char *username = NULL;
	char *chroot_dir = NULL;
        int status;
        long int snaplen;

        snaplen = 65000;
	cnt = -1;
	device = "mon0";

        pd = pcap_create(device, ebuf);
        if (pd == NULL)
                printf("%s", ebuf);

        status = pcap_set_snaplen(pd, snaplen);
        if (status != 0)
                printf("%s: pcap_set_snaplen failed: %s",
                    device, pcap_statustostr(status));
        status = pcap_set_promisc(pd, 1);
        if (status != 0)
                printf("%s: pcap_set_promisc failed: %s",
                    device, pcap_statustostr(status));
        status = pcap_set_timeout(pd, 1000);
        if (status != 0)
                printf("%s: pcap_set_timeout failed: %s",
                    device, pcap_statustostr(status));


        status = pcap_activate(pd);
        if (status < 0) {
                /*
                 * pcap_activate() failed.
                 */
                cp = pcap_geterr(pd);
                if (status == PCAP_ERROR)
                        printf("%s", cp);
                else if ((status == PCAP_ERROR_NO_SUCH_DEVICE ||
                          status == PCAP_ERROR_PERM_DENIED) &&
                         *cp != '\0')
                        printf("%s: %s\n(%s)", device,
                            pcap_statustostr(status), cp);
                else
                        printf("%s: %s", device,
                            pcap_statustostr(status));
        } else if (status > 0) {
                /*
                 * pcap_activate() succeeded, but it's warning us
                 * of a problem it had.
                 */
                cp = pcap_geterr(pd);
                if (status == PCAP_WARNING)
                        printf("%s", cp);
                else if (status == PCAP_WARNING_PROMISC_NOTSUP &&
                         *cp != '\0')
                        printf("%s: %s\n(%s)", device,
                            pcap_statustostr(status), cp);
                else
                        printf("%s: %s", device,
                            pcap_statustostr(status));
        }

        i = pcap_snapshot(pd);
        if (snaplen < i) {
                printf("snaplen raised from %lu to %d", snaplen, i);
                snaplen = i;
        }
        if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
                localnet = 0;
                netmask = 0;
                printf("%s", ebuf);
        }

	if (pcap_compile(pd, &fcode, NULL, 0, netmask) < 0)
		printf("%s", pcap_geterr(pd));

	sigset(SIGPIPE, cleanup);
	sigset(SIGTERM, cleanup);
	sigset(SIGINT, cleanup);
	sigset(SIGCHLD, child_cleanup);
	/* Cooperate with nohup(1) */
	if ((oldhandler = sigset(SIGHUP, cleanup)) != SIG_DFL)
		sigset(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		printf("%s", pcap_geterr(pd));

        callback = print_packet;
        pcap_userdata = (u_char *)&printinfo;

        int dlt;
        const char *dlt_name;

        dlt = pcap_datalink(pd);
        dlt_name = pcap_datalink_val_to_name(dlt);
        if (dlt_name == NULL) {
                (void)fprintf(stderr, "listening on %s, link-type %u, capture size %lu bytes\n",
                    device, dlt, snaplen);
        } else {
                (void)fprintf(stderr, "listening on %s, link-type %s (%s), capture size %lu bytes\n",
                    device, dlt_name,
                    pcap_datalink_val_to_description(dlt), snaplen);
        }
        (void)fflush(stderr);
	status = pcap_loop(pd, cnt, callback, pcap_userdata);

        /*
         * We're printing packets.  Flush the printed output,
         * so it doesn't get intermingled with error output.
         */
        if (status == -2) {
                /*
                 * We got interrupted, so perhaps we didn't
                 * manage to finish a line we were printing.
                 * Print an extra newline, just in case.
                 */
                putchar('\n');
        }
        (void)fflush(stdout);

	if (status == -1) {
		/*
		 * Error.  Report it.
		 */
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
	}

	pcap_close(pd);
	exit(status == -1 ? 1 : 0);
}

/* make a clean exit on interrupts */
static RETSIGTYPE
cleanup(int signo)
{
	alarm(0);
	pcap_breakloop(pd);
	exit(0);
}
static RETSIGTYPE
child_cleanup(int signo)
{
  wait(NULL);
}

static void
print_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct print_info *print_info;
	u_int hdrlen;

	++packets_captured;

        /*ts_print(&h->ts);*/

	print_info = (struct print_info *)user;

	/*
	 * Some printers want to check that they're not walking off the
	 * end of the packet.
	 * Rather than pass it all the way down, we set this global.
	 */
	/*snapend = sp + h->caplen;*/

        /*hdrlen = (*print_info->printer)(h, sp);*/

        putchar('\n');

        hdrlen = ieee802_11_radio_if_print(h, sp);

	putchar('\n');

}

/*
static void
ndo_default_print(netdissect_options *ndo _U_, const u_char *bp, u_int length)
{
	hex_and_ascii_print("\n\t", bp, length); 
}

void
default_print(const u_char *bp, u_int length)
{
	ndo_default_print(gndo, bp, length);
}

static void
ndo_error(netdissect_options *ndo _U_, const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(1);
}

static void
ndo_warning(netdissect_options *ndo _U_, const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

*/
