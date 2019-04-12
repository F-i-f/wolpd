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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/filter.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define WOL_MIN_UDP_SIZE (sizeof(struct udphdr)+ETH_ALEN*17)

#define DEFAULT_PORT  9

#define ETH_P_WOL       0x0842

uint8_t wol_magic[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

struct eth_frame {
    struct ethhdr       head;
    uint8_t             data[ETH_DATA_LEN];
};


const char *progname;

/* global options */
char            *g_input_iface  = NULL;
char            *g_output_iface = NULL;
uint16_t         g_port         = DEFAULT_PORT;
int              g_foregnd      = 0;


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
  -h, --help                    print this help, then exit.\n\
  -v, --version                 print version number, then exit.\n\
  -f, --foreground              don't fork to background.\n\
  -i, --input-interface=IFACE   source network interface.\n\
  -o, --output-interface=IFACE  destination network interface.\n\
  -p, --port=PORT               udp port used for wol packets (default: %i).\n\n\
Report bugs to <%s>.\n",
        PACKAGE_NAME, PACKAGE_NAME,
        DEFAULT_PORT, PACKAGE_BUGREPORT);
    exit(EXIT_SUCCESS);
}

void parse_options(int argc, char *argv[])
{
    int c;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",             0, 0, 'h'},
            {"version",          0, 0, 'v'},
            {"foreground",       0, 0, 'f'},
            {"input-interface",  1, 0, 'i'},
            {"output-interface", 1, 0, 'o'},
            {"port",             1, 0, 'p'},
            {NULL,               0, 0, 0  }
        };

        if ((c = getopt_long(argc, argv, "hvi:o:p:f",
                     long_options, &option_index)) == -1) break;

        switch (c) {
            case 'h':
                usage_and_exit();
                break;
            case 'v':
                version_and_exit();
                break;
            case 'i':
                g_input_iface = optarg;
                break;
            case 'o':
                g_output_iface = optarg;
                break;
            case 'f':
                g_foregnd = 1;
                break;
            case 'p':
                g_port = (uint16_t)atoi(optarg);
                break;
        }
    }
}

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

int setup_filter(int sock) /* returns true on ok, false on failure */
{
    struct sock_fprog prog;
    struct sock_filter filter[] =
        {
         BPF_STMT(BPF_LD  + BPF_H    + BPF_ABS,              12),             /* Ethertype */
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,           ETH_P_IP,   0, 106 ), /* is IP */

         BPF_STMT(BPF_LD  + BPF_B    + BPF_ABS,              14),             /* A = IPversion (4 MSB) + IHL (4 LSB) */
         BPF_STMT(BPF_ALU + BPF_RSH  + BPF_K,                 4),             /* A = IPversion */
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,          IPVERSION,   0, 103 ), /* is IPv4 */

         BPF_STMT(BPF_LD  + BPF_H    + BPF_ABS,              20),             /* Flags + Fragment offset */
         BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K,             0x3fff, 101,   0 ), /* More Fragment == 0 && Frag. id == 0 */

         BPF_STMT(BPF_LD  + BPF_B    + BPF_ABS,              23),             /* IP Proto */
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,                 17,   0,  99 ), /* is UDP */

         BPF_STMT(BPF_LDX + BPF_B    + BPF_MSH,              14),             /* X = number of IPv4 header bytes) */
         BPF_STMT(BPF_LD  + BPF_H    + BPF_IND,              16),             /* X + 14 for Ethernet + 2 UDP dport  */
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,             g_port,   0,  96 ), /* UDP port is g_port */

         BPF_STMT(BPF_LD  + BPF_H    + BPF_IND,              18),             /* X + 14 for Ethernet + 4 UDP length  */
         BPF_JUMP(BPF_JMP + BPF_JGE  + BPF_K,   WOL_MIN_UDP_SIZE,   0,  94 ), /* Size is at least WOL packet */

         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND,              22),             /* UDP payload bytes 0-3 */
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,           (uint)-1,   0,  92 ), /* ff:ff:ff:ff */
         BPF_STMT(BPF_LD  + BPF_H    + BPF_IND,              26),             /* UDP payload bytes 4-5 */
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_K,             0xffff,   0,  90 ), /* ff:ff */

         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND,              28),             /* UDP payload bytes 6-9 */
         BPF_STMT(BPF_ST,                                     0),             /* Store in Mem[0] */
         BPF_STMT(BPF_LD  + BPF_H    + BPF_IND,              32),             /* UDP payload bytes 10-11 */
         BPF_STMT(BPF_ST,                                     1),             /* Store in Mem[1] */

         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND,              34),             /* Compare first copy #1 */
         BPF_STMT(BPF_STX,                                    3),             /* Store X in Mem[3] */
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,               0),
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_X,                 0,    0,  82 ),
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,               3),
         BPF_STMT(BPF_LD  + BPF_H    + BPF_IND,              38),
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,               1),
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_X,                 0,    0,  78 ),

         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,               3),
         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND,              32),             /* UDP payload bytes 10-13 */
         BPF_STMT(BPF_ST,                                     1),             /* Store in Mem[1] */
         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND,              36),             /* UDP payload bytes 14-17 */
         BPF_STMT(BPF_ST,                                     2),             /* Store in Mem[1] */

#define BPF_WOL_MACS_PAYLOAD_CHECK(udpoff, jumpadd)                             \
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,        3),                      \
         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND, udpoff+0),                      \
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,        0),                      \
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_X,          0,    0, jumpadd+9 ),    \
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,        3),                      \
         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND, udpoff+4),                      \
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,        1),                      \
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_X,          0,    0, jumpadd+5 ),    \
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,        3),                      \
         BPF_STMT(BPF_LD  + BPF_W    + BPF_IND, udpoff+8),                      \
         BPF_STMT(BPF_LDX + BPF_W    + BPF_MEM,        2),                      \
         BPF_JUMP(BPF_JMP + BPF_JEQ  + BPF_X,          0,    0, jumpadd+1 )

         BPF_WOL_MACS_PAYLOAD_CHECK( 40, 60),
         BPF_WOL_MACS_PAYLOAD_CHECK( 52, 48),
         BPF_WOL_MACS_PAYLOAD_CHECK( 64, 36),
         BPF_WOL_MACS_PAYLOAD_CHECK( 76, 24),
         BPF_WOL_MACS_PAYLOAD_CHECK( 88, 12),
         BPF_WOL_MACS_PAYLOAD_CHECK(100,  0),

#undef BPF_WOL_MACS_PAYLOAD_CHECK

         BPF_STMT(BPF_RET + BPF_K,                0xffff),           /* Return whole packet */
         BPF_STMT(BPF_RET + BPF_K,                     0),           /* Drop */
        };

    prog.len = sizeof(filter)/sizeof(filter[0]);
    prog.filter = filter;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) != 0) {
        fprintf(stderr, "%s: couldn't attach filter: %s\n",
                progname, strerror(errno));
        return 0; /* fail */
    } else {
        return 1; /* ok */
    }
}

int main(int argc, char *argv[])
{
    const char* ptr;
    int in_socket, out_socket;
    int in_ifindex, out_ifindex;
    struct eth_frame wol_msg;
    ssize_t wol_len, sent_len;
    struct sockaddr_ll in_lladdr, out_lladdr;
    struct iphdr *ip_head;
    struct udphdr *udp_head;
    int i, mismatch;

    progname = argv[0];
    ptr = strrchr(progname, '/');
    if (ptr != NULL) {
        progname = ptr+1;
    }

    parse_options(argc, argv);

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

    /* Set up external/input socket */
    if ((in_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0 ) {
        fprintf(stderr, "%s: couldn't open external socket: %s\n",
                progname, strerror(errno));
        goto exit_fail1;
    }

    if (!setup_filter(in_socket)) {
        goto exit_fail2;
    }

    in_ifindex = get_if_index(in_socket, g_input_iface, "input");
    if (in_ifindex < 0) {
        goto exit_fail2;
    }

    memset(&in_lladdr, 0, sizeof(in_lladdr));
    in_lladdr.sll_family   = AF_PACKET;
    in_lladdr.sll_protocol = htons(ETH_P_IP);
    in_lladdr.sll_ifindex  = in_ifindex;
    in_lladdr.sll_hatype   = ARPHRD_ETHER;
    in_lladdr.sll_pkttype  = PACKET_OTHERHOST;
    in_lladdr.sll_halen    = ETH_ALEN;

    if (bind(in_socket, (struct sockaddr *) &in_lladdr, sizeof(in_lladdr)) < 0) {
        fprintf(stderr, "%s: bind AF_PACKET interface %s at index %d: %s\n",
                progname, g_input_iface, in_ifindex, strerror(errno));
        goto exit_fail2;
    }

    /* Set up internal/output socket */
    if ((out_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0 ) {
        fprintf(stderr, "%s: couldn't open internal socket: %s\n",
                progname, strerror(errno));
        goto exit_fail2;
    }

    out_ifindex = get_if_index(out_socket, g_output_iface, "external");
    if (out_ifindex < 0) {
        goto exit_fail3;
    }

    memset(&out_lladdr, 0, sizeof(out_lladdr));
    out_lladdr.sll_family   = AF_PACKET;
    out_lladdr.sll_protocol = htons(ETH_P_IP);
    out_lladdr.sll_ifindex  = out_ifindex;
    out_lladdr.sll_hatype   = ARPHRD_ETHER;
    out_lladdr.sll_halen    = ETH_ALEN;

    if (g_foregnd == 0) {
        if (daemon(0, 0) != 0) {
            fprintf(stderr, "%s: couldn't fork a background process: %s\n",
                    progname, strerror(errno));
            goto exit_fail3;
        }
    }

    while (1)
    {
        if ((wol_len = recv( in_socket, &wol_msg, sizeof(wol_msg), 0)) < 0) {
            syslog(LOG_ERR, "couldn't receive data from external socket: %m");
            goto exit_fail3;
        }

        ip_head = (struct iphdr*) &wol_msg.data;
        udp_head = (struct udphdr*) ((char*)&wol_msg.data + (ip_head->ihl << 2));

        if (ntohs(wol_msg.head.h_proto) != ETH_P_IP) {
            syslog(LOG_WARNING, "dropped packet with Ethernet protocol 0x%04x from %02X:%02X:%02X:%02X:%02X:%02X",
                   ntohs(wol_msg.head.h_proto),
                   wol_msg.head.h_source[0], wol_msg.head.h_source[1], wol_msg.head.h_source[2],
                   wol_msg.head.h_source[3], wol_msg.head.h_source[4], wol_msg.head.h_source[5]);
            continue;
        }

        if (ip_head->version != IPVERSION) {
            syslog(LOG_WARNING, "dropped packet with IP version %d from %02X:%02X:%02X:%02X:%02X:%02X",
                   ip_head->version,
                   wol_msg.head.h_source[0], wol_msg.head.h_source[1], wol_msg.head.h_source[2],
                   wol_msg.head.h_source[3], wol_msg.head.h_source[4], wol_msg.head.h_source[5]);
            continue;
        }

        if (ip_head->protocol != IPPROTO_UDP) {
            syslog(LOG_WARNING, "dropped packet with IP protocol %d from %s",
                   ip_head->protocol, inet_ntoa(*(struct in_addr*)&ip_head->saddr));
            continue;
        }

        if (ntohs(udp_head->uh_dport) != g_port) {
            syslog(LOG_WARNING, "dropped wrong UDP port %d packet from %s",
                   ntohs(udp_head->uh_dport), inet_ntoa(*(struct in_addr*)&ip_head->saddr));
            continue;
        }

        if (ntohs(udp_head->uh_ulen) != WOL_MIN_UDP_SIZE) {
            syslog(LOG_WARNING, "dropped wrong size %d-byte packet from %s",
                   ntohs(udp_head->uh_ulen), inet_ntoa(*(struct in_addr*)&ip_head->saddr));
            continue;
        }

        if (memcmp(udp_head+1, wol_magic, ETH_ALEN) != 0) {
            syslog(LOG_NOTICE, "dropped non-WOL (missing initial 6 x 0xff) packet from %s",
                   inet_ntoa(*(struct in_addr*)&ip_head->saddr));
            continue;
        }

        mismatch = 0;
        for (i=2; i <= 16; ++i) {
            if (memcmp((unsigned char*)(udp_head+1) + ETH_ALEN,
                       (unsigned char*)(udp_head+1) + ETH_ALEN * i,
                       ETH_ALEN)) {
                syslog(LOG_NOTICE, "dropped non-WOL (mismatch WOP copy #%d) packet from %s",
                       i=1, inet_ntoa(*(struct in_addr*)&ip_head->saddr));
                mismatch=1;
                break;
            }
        }
        if (mismatch)
            continue;

        if ((sent_len = sendto(out_socket, &wol_msg, (size_t) wol_len, 0,
                              (struct sockaddr *) &out_lladdr, sizeof(out_lladdr))) < 0) {
            syslog(LOG_ERR, "cannot forward WOL packet from %s: %m",
                   inet_ntoa(*(struct in_addr*)&ip_head->saddr));
            goto exit_fail3;
        }

        syslog(LOG_NOTICE, "magic packet from %s forwarded to "
            "%2.2hhx:%2.2hhx:%2.2hhx:%2.2hhx:%2.2hhx:%2.2hhx",
            inet_ntoa(*(struct in_addr*)&ip_head->saddr),
            wol_msg.head.h_dest[0], wol_msg.head.h_dest[1],
            wol_msg.head.h_dest[2], wol_msg.head.h_dest[3],
            wol_msg.head.h_dest[4], wol_msg.head.h_dest[5]
        );

        if (wol_len != sent_len) {
            syslog(LOG_WARNING, "short write: %u/%u bytes sent when forwarding packet from %s",
                   (unsigned)sent_len, (unsigned)wol_len,
                   inet_ntoa(*(struct in_addr*)&ip_head->saddr));
            continue;
        }
    }

exit_fail3:
    close(out_socket);

exit_fail2:
    close(in_socket);

exit_fail1:
    return EXIT_FAILURE;
}

/*
  Local variables:
  c-basic-offset: 4
  indent-tabs-mode: nil
  End:
*/
