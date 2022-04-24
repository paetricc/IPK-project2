#ifndef IPK_PROJECT2_PACKETSNIFFER_H
#define IPK_PROJECT2_PACKETSNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

/* pokud se dané číslo nachazí v daných mezích vrátí 1 jinak 0 */
#define BETWEEN(first, number, last)  (((first) <= (number)) && ((number) <= (last)))

/* Čísla IP protokolů z https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers */
#define IP_PROTOCOL_ICMP 0x01 /* ICMP */
#define IP_PROTOCOL_TCP  0x06 /* TCP */
#define IP_PROTOCOL_UDP  0x11 /* UDP */

#define ETHER_HEADER_SIZE 14  /* velikost ethernetové hlavičky */
#define IPV6_HEADER_SIZE  40  /* velikost IPv6 hlavičky */

#define PAYLOAD_ROW_SIZE 16   /* velikost řádku payloadu */
#define BUFSIZE 128           /* velikost bufferů */


/* struktura vyžadováná funcí getopt_long(), aby mohla správně zpracovávat dlouhé zápisy argumentů */
static struct option long_options[] = {
        {"interface", optional_argument, 0, 'i' },
        {"port", required_argument, 0, 'p' },
        {"tcp", no_argument, 0, 't' },
        {"udp", no_argument, 0, 'u' },
        {"icmp", no_argument, 0, 'I' },
        {"arp", no_argument, 0, 'a' },
        {"number", required_argument, 0, 'n' }
};

/* struktura uchovávající výběr z argumentů programu (defaultně vše až na num je nastaveno na 0) */
static struct Options {
    char* interface;
    int   port;
    char  tcp;
    char  udp;
    char  icmp;
    char  arp;
    int   num;
} def_option = {NULL, 0, 0, 0, 0, 0, 1};

typedef struct Options option;

void parse_args(int ,char **, struct Options *);

void interface();

char* make_filter(struct Options *, char *);

void handler(u_char *, const struct pcap_pkthdr *, const u_char *);

void p_payload(const u_char *, int);

void p_arp(const struct ether_arp *);

void p_port_udp(const struct udphdr *);

void p_port_tcp(const struct tcphdr *);

void p_ip(const struct ip *);

void p_ip6(const struct ip6_hdr *);

void p_length(const struct pcap_pkthdr *);

void p_mac(struct ether_header *);

void p_time(time_t, suseconds_t);

#endif //IPK_PROJECT2_PACKETSNIFFER_H
