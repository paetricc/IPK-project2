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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#define BETWEEN(first, number, last)  (((first) <= (number)) && ((number) <= (last)))

#define IP_PROTOCOL_ICMP 0x01
#define IP_PROTOCOL_TCP  0x06
#define IP_PROTOCOL_UDP  0x11

static struct option long_options[] = {
        {"interface", optional_argument, 0, 'i' },
        {"port", required_argument, 0, 'p' },
        {"tcp", no_argument, 0, 't' },
        {"udp", no_argument, 0, 'u' },
        {"icmp", no_argument, 0, 'I' },
        {"arp", no_argument, 0, 'a' },
        {"number", required_argument, 0, 'n' }
};

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

#endif //IPK_PROJECT2_PACKETSNIFFER_H
