/* wolpd - Wake-On-LAN Proxy Daemon
 * Copyright (C) 2010  Federico Simoncelli <federico.simoncelli@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/filter.h>

#if __GNUC__
# define ATTRIBUTE_UNUSED __attribute__((unused))
#else /* ! __GNUC__ */
# define ATTRIBUTE_UNUSED /**/
#endif /* ! __GNUC__ */

#define SOCK_DESCR_IN_ETHER "raw Ethernet input"
#define SOCK_DESCR_IN_UDP   "UDP input"
#define SOCK_DESCR_OUT      "output"

#define WOL_MIN_PAYLOAD_SIZE (ETH_ALEN*17)
#define WOL_MIN_ETHER_RAW_SIZE (sizeof(struct ethhdr)+WOL_MIN_PAYLOAD_SIZE)
#define WOL_MIN_UDP_SIZE (sizeof(struct udphdr)+WOL_MIN_PAYLOAD_SIZE)
#define WOL_MIN_UDP_RAW_SIZE (sizeof(struct ethhdr)+sizeof(struct iphdr)+WOL_MIN_UDP_SIZE)

#define ETH_P_WOL       0x0842

struct eth_frame {
    struct ethhdr       head;
    uint8_t             data[ETH_DATA_LEN];
};

#define VALIDATE_RESULTS_ADDRESS_DESCR_SIZE 64
struct validate_results {
    const char* payload;
    char        saddr_descr[VALIDATE_RESULTS_ADDRESS_DESCR_SIZE];
};

/*
 * Globals
*/
const uint8_t wol_magic[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

const int handled_signals[] = { SIGINT, SIGQUIT, SIGTERM, SIGHUP, 0 };

const char *progname;
volatile int g_interrupt_signum;

/* Options */

/* Chroot() directory */
const char* g_chroot = NULL;

/* Ether Type to listen for WOL packets or ETHERTYPE_NO_LISTEN if not
 * listening to raw ether frames */
#define ETHERTYPE_NO_LISTEN -1
int g_ethertype = ETH_P_WOL;

/* In foreground, don't daemonize if true */
int g_foregnd = 0;

/* Input interface, required */
char *g_input_iface = NULL;

/* Output interface, required */
char *g_output_iface = NULL;

/* User to run as */
struct passwd* g_running_user = NULL;

/* UDP port to listen on or UDP_PORT_NO_LISTEN if not listening to UDP
 * or UDP_PORT_LISTEN_ALL if listening to all UDP ports. */
#define UDP_PORT_NO_LISTEN  -1
#define UDP_PORT_LISTEN_ALL -2
int g_udp_port = -1;

/* Listen promiscuously if true */
int g_promiscuous = 0;

/*
 * Help, usage.
 */

void version_and_exit()
{
    printf("\
%s\n\n\
Copyright (C) 2010 Federico Simoncelli\n\
License GPLv3+: \
GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\n\
Written by Federico Simoncelli.\n",
        PACKAGE_STRING);

    exit(EXIT_SUCCESS);
}

void usage_and_exit()
{
    printf("\
%s is a Wake-On-Lan proxy daemon.\n\n\
Usage: %s [OPTION]...\n\n\
Options:\n\
  -C, --chroot=DIRECTORY        chroot(2) to DIRECTORY.\n\
  -e, --ethertype=ETHERTYPE     Listen for WOL packets with given ethernet type.\n\
                                (Default: 0x%04X)\n\
  -E, --no-ether                Do not listen for raw ethernet WOL packets.\n\
  -f, --foreground              Don't fork to background.\n\
  -h, --help                    Print this help, then exit.\n\
  -i, --input-interface=IFACE   Source network interface.\n\
  -o, --output-interface=IFACE  Destination network interface.\n\
  -p, --port=PORT               UDP port used for WOL packets.\n\
                                Implies --udp.\n\
  -P, --promiscuous             Put the input interface in promiscuous mode.\n\
  -s, --setuid=USER             Change the process user if to USER after\n\
                                initialization.\n\
                                (Default: keep running as root)\n\
  -u, --udp                     Listens to UDP WOL packets.\n\
                                Unless a PORT is specified with --port, listens\n\
                                to *all* UDP ports.\n\
  -U, --no-udp                  Do not listen for WOL packets on UDP. (default)\n\
  -v, --version                 Print version number, then exit.\n\n\
Report bugs to <%s>.\n",
           PACKAGE_NAME, PACKAGE_NAME,
           ETH_P_WOL, PACKAGE_BUGREPORT);
    exit(EXIT_SUCCESS);
}

int parse_uint16(const char *descr, const char *num)
/* If returns >= 0, the 16-bit value.  Otherwise, an error
 * occurred. */
{
    char *ptr;
    long result;

    result = strtol(num, &ptr, 0);

    if (*ptr) {
        fprintf(stderr, "%s: cannot parse \"%s\" as a %s.\n",
                progname, num, descr);
        return -1;
    }

    if (result < 0 || result >= 1<<16) {
        fprintf(stderr, "%s: %ld is an invalid %s (must be in range 0..65535).\n",
                progname, result, descr);
        return -1;
    }

    return (int)result;
}

void parse_options(int argc, char *argv[])
{
    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] =
            {
             {"chroot",           1, 0, 'C'},
             {"ethertype",        1, 0, 'e'},
             {"no-ether",         0, 0, 'E'},
             {"foreground",       0, 0, 'f'},
             {"help",             0, 0, 'h'},
             {"input-interface",  1, 0, 'i'},
             {"output-interface", 1, 0, 'o'},
             {"port",             1, 0, 'p'},
             {"promiscuous",      1, 0, 'P'},
             {"setuid",           1, 0, 's'},
             {"udp",              0, 0, 'u'},
             {"no-udp",           0, 0, 'U'},
             {"version",          0, 0, 'v'},
             {NULL,               0, 0, 0  }
            };

        if ((c = getopt_long(argc, argv, "C:e:Efhi:o:p:Ps:uUv",
                     long_options, &option_index)) == -1) break;

        switch (c) {
        case 'C':
            g_chroot = optarg;
            break;
        case 'e':
            g_ethertype = parse_uint16("Ether Type", optarg);
            if (g_ethertype < 0) {
                exit(EXIT_FAILURE);
            }
            break;
        case 'E':
            g_ethertype = ETHERTYPE_NO_LISTEN;
            break;
        case 'f':
            g_foregnd = 1;
            break;
        case 'h':
            usage_and_exit();
            break;
        case 'i':
            g_input_iface = optarg;
            break;
        case 'o':
            g_output_iface = optarg;
            break;
        case 'p':
            g_udp_port = parse_uint16("UDP port", optarg);
            if (g_udp_port < 0) {
                exit(EXIT_FAILURE);
            }
            break;
        case 'P':
            g_promiscuous = 1;
            break;
        case 's':
            {
                int fail_errno = 0;

                errno = 0;
                g_running_user = getpwnam(optarg);
                fail_errno = errno;

                if (g_running_user == NULL) {
                    char *ptr;
                    uid_t uid;
                    uid = (uid_t)strtol(optarg, &ptr, 0);
                    if (!*ptr) {
                        errno = 0;
                        g_running_user = getpwuid(uid);
                        fail_errno = errno;
                    }
                }

                if (g_running_user == NULL) {
                    fprintf(stderr, "%s: cannot find user \"%s\": %s\n",
                            progname, optarg,
                            fail_errno ? strerror(fail_errno) : "not found");
                    exit(EXIT_FAILURE);
                }
            }
            break;
        case 'u':
            if (g_udp_port == UDP_PORT_NO_LISTEN) {
                g_udp_port = UDP_PORT_LISTEN_ALL;
            }
            break;
        case 'U':
            g_udp_port = UDP_PORT_NO_LISTEN;
            break;
        case 'v':
            version_and_exit();
            break;
        }
    }

    if (g_input_iface == NULL) {
        fprintf(stderr, "%s: no input interface provided, use -i <interface>\n",
                progname);
        exit(EXIT_FAILURE);
    }

    if (g_output_iface == NULL) {
        fprintf(stderr, "%s: no output interface provided, use -o <interface>\n",
                progname);
        exit(EXIT_FAILURE);
    }

    if (g_udp_port == UDP_PORT_NO_LISTEN && g_ethertype == ETHERTYPE_NO_LISTEN) {
        fprintf(stderr, "%s: listening both off on UDP and raw Ethernet, nothing to do\n",
                progname);
        exit(EXIT_FAILURE);
    }
}

const char* get_features()
{
    char buf_ether[32];
    char buf_udp[32];
    char buf_userinfo[64];
    static char buf_features[32 + sizeof(buf_ether) + sizeof(buf_udp) + sizeof(buf_userinfo)];

    if (g_ethertype == ETHERTYPE_NO_LISTEN) {
        buf_ether[0] = '\0';
    } else {
        snprintf(buf_ether, sizeof(buf_ether),
                 "Ethernet type 0x%04x",
                 g_ethertype);
    }

    switch (g_udp_port) {
    case UDP_PORT_NO_LISTEN:
        buf_udp[0] = '\0';
        break;
    case UDP_PORT_LISTEN_ALL:
        snprintf(buf_udp, sizeof(buf_udp),
                 "all UDP ports");
        break;
    default:
        snprintf(buf_udp, sizeof(buf_udp),
                 "UDP port %d",
                 g_udp_port);
        break;
    }

    if (g_running_user == NULL) {
        buf_userinfo[0] = '\0';
    } else {
        snprintf(buf_userinfo, sizeof(buf_userinfo),
                 ", running as %s (uid=%lu)",
                 g_running_user->pw_name,
                 (unsigned long)g_running_user->pw_uid);
    }

    snprintf(buf_features, sizeof(buf_features),
             "listening%s for %s%s%s%s",
             g_promiscuous ? " promiscuously" : "",
             buf_ether,
             (buf_ether[0] && buf_udp[0]) ? ", " : "",
             buf_udp,
             buf_userinfo);

    return buf_features;
}


/*
 * BPF code
 */

/* Since almost all the BPF jumps go to the last instruction, automate
 * the offset calculations.
 * Use JEND to mark a jump to the end */
#define JEND 255

int setup_filter(int sock,
                 const struct sock_filter *filter_preamble,
                 size_t filter_preamble_stmts)
/* returns true on ok, false on failure */
{
    /* The payload filter expects the X index register to contain the
     * offset to the payload. */
    static const struct sock_filter filter_payload[] =
        {
         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,                     0),               /* UDP payload bytes 0-3 */
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_K,                 (uint)-1,    0, JEND ), /* ff:ff:ff:ff */
         BPF_STMT(BPF_LD   + BPF_H    + BPF_IND,                     4),               /* UDP payload bytes 4-5 */
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_K,                   0xffff,    0, JEND ), /* ff:ff */

         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,                     6),               /* UDP payload bytes 6-9 */
         BPF_STMT(BPF_ST,                                            0),               /* Store in Mem[0] */
         BPF_STMT(BPF_LD   + BPF_H    + BPF_IND,                    10),               /* UDP payload bytes 10-11 */
         BPF_STMT(BPF_ST,                                            1),               /* Store in Mem[1] */

         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,                    12),               /* Compare first copy #1 */
         BPF_STMT(BPF_STX,                                           3),               /* Store X in Mem[3] */
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     0),
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_X,                       0,     0, JEND ),
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     3),
         BPF_STMT(BPF_LD   + BPF_H    + BPF_IND,                    16),
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     1),
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_X,                       0,     0, JEND ),

         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     3),
         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,                    10),               /* UDP payload bytes 10-13 */
         BPF_STMT(BPF_ST,                                            1),               /* Store in Mem[1] */
         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,                    14),               /* UDP payload bytes 14-17 */
         BPF_STMT(BPF_ST,                                            2),               /* Store in Mem[1] */

#define BPF_WOL_MACS_PAYLOAD_CHECK(udpoff)                                              \
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     3),                 \
         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,              udpoff+0),                 \
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     0),                 \
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_X,                       0,     0, JEND ),   \
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     3),                 \
         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,              udpoff+4),                 \
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     1),                 \
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_X,                       0,     0, JEND ),   \
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     3),                 \
         BPF_STMT(BPF_LD   + BPF_W    + BPF_IND,              udpoff+8),                 \
         BPF_STMT(BPF_LDX  + BPF_W    + BPF_MEM,                     2),                 \
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_X,                       0,     0, JEND )

         BPF_WOL_MACS_PAYLOAD_CHECK( 18),
         BPF_WOL_MACS_PAYLOAD_CHECK( 30),
         BPF_WOL_MACS_PAYLOAD_CHECK( 42),
         BPF_WOL_MACS_PAYLOAD_CHECK( 54),
         BPF_WOL_MACS_PAYLOAD_CHECK( 66),
         BPF_WOL_MACS_PAYLOAD_CHECK( 78),
         BPF_WOL_MACS_PAYLOAD_CHECK( 90),

#undef BPF_WOL_MACS_PAYLOAD_CHECK

         BPF_STMT(BPF_RET  + BPF_K,                             0xffff),               /* Return whole packet */
         BPF_STMT(BPF_RET  + BPF_K,                                  0),               /* Drop */
        };

    struct sock_fprog prog;
    int ret;
    int i;
    int saved_errno;

    /* Assemble the full BPF program */
    prog.len = sizeof(filter_payload)/sizeof(filter_payload[0]) + filter_preamble_stmts;
    prog.filter = (struct sock_filter *)malloc(sizeof(filter_payload[0]) * prog.len);
    if (prog.filter == NULL) {
        fprintf(stderr, "%s: couldn't allocate %u bytes of memory: %s\n",
                progname, (unsigned)sizeof(filter_payload[0]) * prog.len, strerror(errno));
        return 0; /* fail */
    }

    memcpy(prog.filter, filter_preamble, sizeof(filter_preamble[0]) * filter_preamble_stmts);
    memcpy(prog.filter + filter_preamble_stmts, filter_payload, sizeof(filter_payload));

    for (i=0; i < prog.len; ++i) {
        if (prog.filter[i].jt == JEND) {
            prog.filter[i].jt = prog.len-i-2;
        }
        if (prog.filter[i].jf == JEND) {
            prog.filter[i].jf = prog.len-i-2;
        }
    }

    ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    saved_errno = errno;

    free(prog.filter);

    if (ret != 0) {
        fprintf(stderr, "%s: couldn't attach filter: %s\n",
                progname, strerror(saved_errno));
        return 0; /* fail */
    } else {
        return 1; /* ok */
    }
}

int setup_udp_filter(int sock)
/* returns true on ok, false on failure */
{
    static const struct sock_filter filter_udp_1[] =
        {
         BPF_STMT(BPF_LD   + BPF_W    + BPF_LEN,                     0),               /* Frame length */
         BPF_JUMP(BPF_JMP  + BPF_JGE  + BPF_K,     WOL_MIN_UDP_RAW_SIZE,    0, JEND ), /* is big enough */

         BPF_STMT(BPF_LD   + BPF_H    + BPF_ABS,                    12),               /* Ethertype */
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_K,                 ETH_P_IP,    0, JEND ), /* is IP */

         BPF_STMT(BPF_LD   + BPF_B    + BPF_ABS,                    14),               /* A = IPversion (4 MSB) + IHL (4 LSB) */
         BPF_STMT(BPF_ALU  + BPF_RSH  + BPF_K,                       4),               /* A = IPversion */
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_K,                IPVERSION,    0, JEND ), /* is IPv4 */

         BPF_STMT(BPF_LD   + BPF_H    + BPF_ABS,                    20),               /* Flags + Fragment offset */
         BPF_JUMP(BPF_JMP  + BPF_JSET + BPF_K,                   0x3fff, JEND,    0 ), /* More Fragment == 0 && Frag. id == 0 */

         BPF_STMT(BPF_LD   + BPF_B    + BPF_ABS,                    23),               /* IP Proto */
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_K,              IPPROTO_UDP,    0, JEND ), /* is UDP */

         BPF_STMT(BPF_LDX  + BPF_B    + BPF_MSH,                    14),               /* X = number of IPv4 header bytes) */
        };

    const struct sock_filter filter_udp_port[] =
        {
         BPF_STMT(BPF_LD   + BPF_H    + BPF_IND,                    16),               /* X + 14 for Ethernet + 2 UDP dport  */
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_K,               g_udp_port,    0, JEND ), /* UDP port is g_udp_port */
        };

    static const struct sock_filter filter_udp_2[] =
        {
         BPF_STMT(BPF_LD   + BPF_H    + BPF_IND,                    18),               /* X + 14 for Ethernet + 4 UDP length  */
         BPF_JUMP(BPF_JMP  + BPF_JGE  + BPF_K,         WOL_MIN_UDP_SIZE,    0, JEND ), /* Size is at least WOL packet */

         BPF_STMT(BPF_MISC + BPF_TXA,                                0),               /* A <- X */
         BPF_STMT(BPF_ALU  + BPF_ADD  + BPF_K,                      22),               /* A = offset to beginning of UDP payload */
         BPF_STMT(BPF_MISC + BPF_TAX,                                0),               /* X <- A */
        };

    size_t filter_len;
    struct sock_filter *filter;
    struct sock_filter *filter_ptr;
    int ret;

    filter_len = sizeof(filter_udp_1)/sizeof(filter_udp_1[0])
        + sizeof(filter_udp_2)/sizeof(filter_udp_2[0]);

    if (g_udp_port != UDP_PORT_LISTEN_ALL) {
        filter_len += sizeof(filter_udp_port)/sizeof(filter_udp_port[0]);
    }

    filter = (struct sock_filter *)malloc(sizeof(filter_udp_1[0]) * filter_len);
    if (filter == NULL) {
        fprintf(stderr, "%s: couldn't allocate %u bytes of memory: %s\n",
                progname, (unsigned)(sizeof(filter_udp_1[0]) * filter_len), strerror(errno));
        return 0; /* fail */
    }

    filter_ptr = filter;

    memcpy(filter, filter_udp_1, sizeof(filter_udp_1));
    filter_ptr += sizeof(filter_udp_1)/sizeof(filter_udp_1[0]);

    if (g_udp_port != UDP_PORT_LISTEN_ALL) {
        memcpy(filter_ptr , filter_udp_port, sizeof(filter_udp_port));
        filter_ptr += sizeof(filter_udp_port)/sizeof(filter_udp_port[0]);
    }

    memcpy(filter_ptr, filter_udp_2, sizeof(filter_udp_2));

    ret = setup_filter(sock, filter, filter_len);

    free(filter);

    return ret;
}

int setup_ether_filter(int sock)
/* returns true on ok, false on failure */
{
    const struct sock_filter filter_ether[] =
        {
         BPF_STMT(BPF_LD   + BPF_W    + BPF_LEN,                     0),               /* Frame length */
         BPF_JUMP(BPF_JMP  + BPF_JGE  + BPF_K,   WOL_MIN_ETHER_RAW_SIZE,    0, JEND ), /* is big enough */

         BPF_STMT(BPF_LD   + BPF_H    + BPF_ABS,                    12),               /* Ethertype */
         BPF_JUMP(BPF_JMP  + BPF_JEQ  + BPF_K,              g_ethertype,    0, JEND ), /* is the selected Ether Type */

         BPF_STMT(BPF_LDX  + BPF_W    + BPF_K,                      14),               /* X = offset to Ethernet payload */
        };

    return setup_filter(sock, filter_ether, sizeof(filter_ether)/sizeof(filter_ether[0]));
}

#undef JEND

/*
 * Utilities
 */

ssize_t read_packet(int sock, const char* sock_descr, void *buf, size_t buf_size)
/* Returns -1 if an error occured, -2 if no packets are available or
   the size of the received packet. A zero-byte packet is converted to an error (-1) */
{
    ssize_t recv_len;

    while (1) {
        if ((recv_len = recv( sock, buf, buf_size, 0)) < 0) {
            switch(errno) {
            case EAGAIN:
                return -2;
            case EINTR:
                continue; /* the while() loop */
            default:
                syslog(LOG_ERR, "couldn't receive data from %s socket: %m", sock_descr);
                return -1;
            }
        }

        if (recv_len == 0) {
            syslog(LOG_ERR, "end of file on %s socket", sock_descr);
            return -1;
        }

        return recv_len;
    }
}


/*
 * Raw socket setup
 */

int get_if_index(int sock, const char *if_name, const char *if_description)
{
    struct ifreq ifhw;
    memset(&ifhw, 0, sizeof(ifhw));
    strncpy(ifhw.ifr_name, if_name, sizeof(ifhw.ifr_name));

   if (ioctl(sock, SIOCGIFINDEX, &ifhw) < 0) {
        fprintf(stderr, "%s: couldn't find %s interface %s: %s\n",
                progname, if_description, if_name, strerror(errno));
        return -1;
    }

   return ifhw.ifr_ifindex;
}

int set_promiscuous(int sock, const char *ifname, int ifindex) /* returns true on ok, false on failure */
{
    struct packet_mreq mreq;

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifindex;
    mreq.mr_type    = PACKET_MR_PROMISC;

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
        fprintf(stderr, "%s: cannot add promiscuous membership on interface \"%s\" at index %d: %s\n",
                progname, ifname, ifindex, strerror(errno));
        return 0;
    } else {
        return 1;
    }
}

int setup_input_socket(uint16_t ethertype,
                       const char* sock_description,
                       int (*setup_filter_function)(int))
/* Return the socket fd or -1 if failed */
{
    struct sockaddr_ll lladdr;
    int                sock;
    int                ifindex;
    int                flags;
    int                flushing;
    ssize_t            recv_len;
    char               recv_buf[1];

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ethertype))) < 0 ) {
        fprintf(stderr, "%s: couldn't open %s socket: %s\n",
                progname, sock_description, strerror(errno));
        return -1;
    }

    if (!setup_filter_function(sock)) {
        goto exit_fail;
    }

    ifindex = get_if_index(sock, g_input_iface, sock_description);
    if (ifindex < 0) {
        goto exit_fail;
    }

    memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_family   = AF_PACKET;
    lladdr.sll_protocol = htons(ethertype);
    lladdr.sll_ifindex  = ifindex;
    lladdr.sll_hatype   = ARPHRD_ETHER;
    lladdr.sll_pkttype  = PACKET_OTHERHOST;
    lladdr.sll_halen    = ETH_ALEN;

    if (bind(sock, (struct sockaddr *) &lladdr, sizeof(lladdr)) < 0) {
        fprintf(stderr, "%s: bind AF_PACKET %s interface %s at index %d: %s\n",
                progname, sock_description, g_input_iface, ifindex, strerror(errno));
        goto exit_fail;
    }

    if (g_promiscuous && ! set_promiscuous(sock, g_input_iface, ifindex)) {
        goto exit_fail;
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        fprintf(stderr, "%s: fcntl(F_GETFL) on %s socket: %s\n",
                progname, sock_description, strerror(errno));
        goto exit_fail;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        fprintf(stderr, "%s: fcntl(F_SETFL) on %s socket: %s\n",
                progname, sock_description, strerror(errno));
        goto exit_fail;
    }

    /* Flush any packets on the socket that may have sneaked in before
     * the BPF filter and bind() went into effect. */
    for (flushing=1; flushing; ) {
        switch(recv_len = read_packet(sock, sock_description, &recv_buf, sizeof(recv_buf))) {
        case -1:
            goto exit_fail;
        case -2:
            flushing = 0;
            break;
        default:
            /* Packet has been eaten */
            break;
        }
    }

    return sock;

 exit_fail:
    close(sock);
    return -1;
}

void fill_lladdr(struct sockaddr_ll *lladdr, uint16_t ethertype, int ifindex)
{
    memset(lladdr, 0, sizeof(*lladdr));
    lladdr->sll_family   = AF_PACKET;
    lladdr->sll_protocol = htons(ethertype);
    lladdr->sll_ifindex  = ifindex;
    lladdr->sll_hatype   = ARPHRD_ETHER;
    lladdr->sll_halen    = ETH_ALEN;
}

/*
 * Queue processing
 */

int forward_packets(int in_sock, const
                    char* in_sock_descr,
                    size_t min_packet_size,
                    uint16_t ethertype,
                    int (*validate_packet)(struct validate_results*, const struct eth_frame*, const char*),
                    int out_sock,
                    const struct sockaddr_ll *dst_addr)
/* returns true on ok, false on failure */
{
    struct eth_frame        wol_msg;
    struct validate_results validation_results;
    ssize_t                 wol_len, sent_len;
    int                     i, mismatch;

    while (1) {

        switch (wol_len = read_packet(in_sock, in_sock_descr, &wol_msg, sizeof(wol_msg))) {
        case -1:
            return 0;
        case -2:
            return 1;
        default:
            break;
        }

        if ((size_t)wol_len < min_packet_size) {
            syslog(LOG_ERR, "short packet (%lu < %lu) on %s socket",
                   (unsigned long)wol_len, (unsigned long)min_packet_size, in_sock_descr);
            continue;
        }

        if (ntohs(wol_msg.head.h_proto) != ethertype) {
            syslog(LOG_WARNING, "dropped %s packet with Ethernet protocol 0x%04x from %02x:%02x:%02x:%02x:%02x:%02x",
                   in_sock_descr,
                   ntohs(wol_msg.head.h_proto),
                   wol_msg.head.h_source[0], wol_msg.head.h_source[1], wol_msg.head.h_source[2],
                   wol_msg.head.h_source[3], wol_msg.head.h_source[4], wol_msg.head.h_source[5]);
            continue;
        }


        if ( ! validate_packet(&validation_results, &wol_msg, in_sock_descr) ) {
            continue;
        }

        if (memcmp(validation_results.payload, wol_magic, ETH_ALEN) != 0) {
            syslog(LOG_NOTICE, "dropped %s non-WOL (missing initial 6 x 0xff) packet from %s",
                   in_sock_descr, validation_results.saddr_descr);
            continue;
        }

        mismatch = 0;
        for (i=1; i < 16; ++i) {
            if (memcmp(validation_results.payload + ETH_ALEN,
                       validation_results.payload + ETH_ALEN * (i+1),
                       ETH_ALEN)) {
                syslog(LOG_NOTICE, "dropped %s non-WOL (mismatch WOP copy #%d) packet from %s",
                       in_sock_descr, i, validation_results.saddr_descr);
                mismatch=1;
                break;
            }
        }
        if (mismatch)
            continue;

    send_again:
        if ((sent_len = sendto(out_sock, &wol_msg, (size_t) wol_len, 0,
                               (const struct sockaddr *) dst_addr, sizeof(*dst_addr))) < 0) {
            switch (errno) {
            case EINTR:
                goto send_again;
            default:
                syslog(LOG_ERR, "cannot forward %s WOL packet from %s: %m",
                       in_sock_descr, validation_results.saddr_descr);
                continue; /* the while(1) loop */
            }
        }

        syslog(LOG_NOTICE, "magic %s packet from %s forwarded to "
               "%02x:%02x:%02x:%02x:%02x:%02x",
               in_sock_descr, validation_results.saddr_descr,
               wol_msg.head.h_dest[0], wol_msg.head.h_dest[1],
               wol_msg.head.h_dest[2], wol_msg.head.h_dest[3],
               wol_msg.head.h_dest[4], wol_msg.head.h_dest[5]
               );

        if (wol_len != sent_len) {
            syslog(LOG_WARNING, "short write: %u/%u bytes sent when forwarding %s packet from %s",
                   (unsigned)sent_len, (unsigned)wol_len,
                   in_sock_descr, validation_results.saddr_descr);
            continue;
        }
    }
}

int validate_ether_packet(struct validate_results *results,
                          const struct eth_frame* frame,
                          ATTRIBUTE_UNUSED const char*  sock_descr)
/* returns true on ok, false on failure */
{
    snprintf(results->saddr_descr, sizeof(results->saddr_descr),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             frame->head.h_source[0], frame->head.h_source[1],
             frame->head.h_source[2], frame->head.h_source[3],
             frame->head.h_source[4], frame->head.h_source[5]);
    results->payload = (const char*)&frame->data;

    return 1;
}

int forward_ether(int in_sock, int out_sock, const struct sockaddr_ll *dst_addr)
/* returns true on ok, false on failure */
{
    return forward_packets(in_sock, "raw Ethernet",
                           WOL_MIN_ETHER_RAW_SIZE, g_ethertype,
                           & validate_ether_packet,
                           out_sock, dst_addr);
}

int validate_udp_packet(struct validate_results *results,
                        const struct eth_frame* frame,
                        const char* sock_descr)
/* returns true on ok, false on failure */
{
    struct iphdr *ip_head;
    struct udphdr *udp_head;

    ip_head = (struct iphdr*) frame->data;
    udp_head = (struct udphdr*) ((char*)frame->data + (ip_head->ihl << 2));

    if (ip_head->version != IPVERSION) {
        syslog(LOG_WARNING, "dropped %s packet with IP version %d from %02X:%02X:%02X:%02X:%02X:%02X",
               sock_descr,
               ip_head->version,
               frame->head.h_source[0], frame->head.h_source[1], frame->head.h_source[2],
               frame->head.h_source[3], frame->head.h_source[4], frame->head.h_source[5]);
        return 0;
    }

    if (g_udp_port == UDP_PORT_LISTEN_ALL) {
        snprintf(results->saddr_descr, sizeof(results->saddr_descr),
                 "%s (UDP dport %d)",
                 inet_ntoa(*(struct in_addr*)&ip_head->saddr),
                 ntohs(udp_head->uh_dport));
    } else {
        snprintf(results->saddr_descr, sizeof(results->saddr_descr),
                 "%s",
                 inet_ntoa(*(struct in_addr*)&ip_head->saddr));
    }

    if (ip_head->protocol != IPPROTO_UDP) {
        syslog(LOG_WARNING, "dropped %s packet with IP protocol %d from %s",
               sock_descr, ip_head->protocol, results->saddr_descr);
        return 0;
    }

    if (g_udp_port != UDP_PORT_LISTEN_ALL && ntohs(udp_head->uh_dport) != g_udp_port) {
        syslog(LOG_WARNING, "dropped %s wrong UDP port %d packet from %s",
               sock_descr, ntohs(udp_head->uh_dport), results->saddr_descr);
        return 0;
    }

    if (ntohs(udp_head->uh_ulen) < WOL_MIN_UDP_SIZE) {
        syslog(LOG_WARNING, "dropped %s packet with wrong size %d-byte packet from %s",
               sock_descr, ntohs(udp_head->uh_ulen), results->saddr_descr);
        return 0;
    }

    results->payload = (const char*)(udp_head+1);

    return 1;
}

int forward_udp(int in_sock, int out_sock, const struct sockaddr_ll *dst_addr)
/* returns true on ok, false on failure */
{
    return forward_packets(in_sock, "UDP",
                           WOL_MIN_UDP_RAW_SIZE, ETH_P_IP,
                           & validate_udp_packet,
                           out_sock, dst_addr);
}

/*
 * Signal handlers
 */

void handle_signal(int signum)
{
    g_interrupt_signum = signum;
}

/*
 * Main
 */

int main(int argc, char *argv[])
{
    const char* ptr;
    int in_socket_ether = -1;
    int in_socket_udp = -1;
    int out_socket;
    int out_ifindex;
    struct sockaddr_ll out_lladdr_udp;
    struct sockaddr_ll out_lladdr_ether;
    int max_fd = -1;
    fd_set scan_set;
    fd_set ret_set;
    int select_ret;
    struct sigaction sigact;
    const int *p_int;
    int exit_code = EXIT_FAILURE;

    progname = argv[0];
    ptr = strrchr(progname, '/');
    if (ptr != NULL) {
        progname = ptr+1;
    }

    parse_options(argc, argv);

    /* Set up input socket(s) */
    FD_ZERO(&scan_set);

    if (g_ethertype != ETHERTYPE_NO_LISTEN) {
        in_socket_ether = setup_input_socket(g_ethertype, SOCK_DESCR_IN_ETHER,  &setup_ether_filter);
        if (in_socket_ether < 0) {
            goto exit_fail2;
        }
        FD_SET(in_socket_ether, &scan_set);
        if (in_socket_ether >= max_fd) {
            max_fd = in_socket_ether+1;
        }
    }

    if (g_udp_port != UDP_PORT_NO_LISTEN) {
        in_socket_udp = setup_input_socket(ETH_P_IP, SOCK_DESCR_IN_UDP, &setup_udp_filter);
        if (in_socket_udp < 0) {
            goto exit_fail1;
        }
        FD_SET(in_socket_udp, &scan_set);
        if (in_socket_udp >= max_fd) {
            max_fd = in_socket_udp+1;
        }
    }

    /* Set up output socket */
    if ((out_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0 ) {
        fprintf(stderr, "%s: couldn't %s output socket: %s\n",
                progname, SOCK_DESCR_OUT, strerror(errno));
        goto exit_fail3;
    }

    out_ifindex = get_if_index(out_socket, g_output_iface, SOCK_DESCR_OUT);
    if (out_ifindex < 0) {
        goto exit_fail4;
    }

    /* Initialize syslog before an eventual chroot, it may be too late
     * to connect to syslog after chroot() */
    openlog(progname,
            LOG_CONS|LOG_NDELAY| (g_foregnd ? LOG_PERROR : 0) | LOG_PID,
            LOG_DAEMON);

    /* Chroot if requested */
    if (g_chroot != NULL) {
        if (chdir(g_chroot) != 0) {
            fprintf(stderr, "%s: while chroot()ing: couldn't chdir to \"%s\": %s\n",
                    progname, g_chroot, strerror(errno));
            goto exit_fail3;
        }
        if (chroot(g_chroot) != 0) {
            fprintf(stderr, "%s: while chroot()ing: couldn't chroot to \"%s\": %s\n",
                    progname, g_chroot, strerror(errno));
            goto exit_fail3;
        }
    }

    /* Root is not needed anymore, drop it if requested */
    if (g_running_user != NULL) {
        if (initgroups(g_running_user->pw_name, g_running_user->pw_gid) != 0) {
            fprintf(stderr, "%s: initgroups(\"%s\", %lu) failed: %s\n",
                    progname, g_running_user->pw_name,
                    (unsigned long)g_running_user->pw_gid,
                    strerror(errno));
            goto exit_fail3;
        }
        if (setresgid(g_running_user->pw_gid,
                      g_running_user->pw_gid,
                      g_running_user->pw_gid) != 0) {
            fprintf(stderr, "%s: setresgid(%lu, %lu, %lu) failed: %s\n",
                    progname,
                    (unsigned long)g_running_user->pw_gid,
                    (unsigned long)g_running_user->pw_gid,
                    (unsigned long)g_running_user->pw_gid,
                    strerror(errno));
            goto exit_fail3;
        }
        if (setresuid(g_running_user->pw_uid,
                      g_running_user->pw_uid,
                      g_running_user->pw_uid) != 0) {
            fprintf(stderr, "%s: setresuid(%lu, %lu, %lu) failed: %s\n",
                    progname,
                    (unsigned long)g_running_user->pw_uid,
                    (unsigned long)g_running_user->pw_uid,
                    (unsigned long)g_running_user->pw_uid,
                    strerror(errno));
            goto exit_fail3;
        }
    }

    if (in_socket_ether >= 0) {
        fill_lladdr(&out_lladdr_ether, g_ethertype, out_ifindex);
    }

    if (in_socket_udp >= 0) {
        fill_lladdr(&out_lladdr_udp, ETH_P_IP, out_ifindex);
    }

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = &handle_signal;
    sigact.sa_flags   = SA_RESTART;
    sigemptyset(&sigact.sa_mask);
    for (p_int = handled_signals; *p_int; ++p_int) {
        if (sigaction(*p_int, &sigact, NULL) != 0) {
            fprintf(stderr, "%s: couldn't trap signal %d: %s\n",
                    progname, *p_int, strerror(errno));
            goto exit_fail4;
        }
    }

    if (g_foregnd == 0) {
        if (daemon(0, 0) != 0) {
            fprintf(stderr, "%s: couldn't fork a background process: %s\n",
                    progname, strerror(errno));
            goto exit_fail4;
        }
    }

    syslog(LOG_NOTICE, "started, %s",
           get_features());

    g_interrupt_signum = 0;
    while (! g_interrupt_signum)
    {
        ret_set = scan_set;
        select_ret = select(max_fd, &ret_set, NULL, NULL, NULL);
        if (select_ret < 0) {
            switch(errno) {
            case EINTR:
                continue; /* the while() loop */
            default:
                syslog(LOG_ERR, "select(): %m");
                goto exit_fail5;
            }
        } else if (select_ret == 0) {
            syslog(LOG_ERR, "select() returned zero file descriptors");
            goto exit_fail5;
        }

        if (in_socket_ether >= 0
            && FD_ISSET(in_socket_ether, &ret_set)
            && ! forward_ether(in_socket_ether, out_socket, &out_lladdr_ether)) {
            goto exit_fail5;
        }

        if (in_socket_udp >= 0
            && FD_ISSET(in_socket_udp, &ret_set)
            && ! forward_udp(in_socket_udp, out_socket, &out_lladdr_udp)) {
            goto exit_fail5;
        }
    }

    syslog(LOG_NOTICE, "exiting on signal %d", g_interrupt_signum);
    goto exit_fail4;

 exit_fail5:
    if (! g_foregnd) {
        syslog(LOG_ERR, "exiting on failure");
    }

 exit_fail4:
    close(out_socket);

 exit_fail3:
    if (in_socket_ether >= 0) {
        close(in_socket_ether);
    }

 exit_fail2:
    if (in_socket_udp >= 0) {
        close(in_socket_udp);
    }

 exit_fail1:
    return exit_code;
}

/*
  Local variables:
  c-basic-offset: 4
  indent-tabs-mode: nil
  End:
*/
