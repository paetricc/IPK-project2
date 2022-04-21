//
// Created by bartu on 21.04.22.
//

#ifndef IPK_PROJECT2_PACKETSNIFFER_H
#define IPK_PROJECT2_PACKETSNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap.h>

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
} def_option = {NULL, 0, 0, 0, 0, 0, 0};

typedef struct Options option;

void parse_args(int ,char **, struct Options*);

#endif //IPK_PROJECT2_PACKETSNIFFER_H
