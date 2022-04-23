#include "packetsniffer.h"

void debug(struct Options option) {
    printf("Interface is %s\n", option.interface);
    printf("Port is %d\n", option.port);
    printf("Tcp is %d\n", option.tcp);
    printf("Udp is %d\n", option.udp);
    printf("Icmp is %d\n", option.icmp);
    printf("Arp is %d\n", option.arp);
    printf("Number is %d\n", option.num);
}

void p_time(time_t time, suseconds_t m_second) {
    char buffer[128];
    char z_buffer[6];
    struct tm *info = localtime(&time);

    strftime(buffer, sizeof(buffer), "%FT%T", info);
    strftime(z_buffer, sizeof(z_buffer), "%z", info);

    printf("timestamp: %s.%.3ld%s\n", buffer, m_second / 1000, z_buffer);
}

void p_mac(struct ether_header *eth_header) {
    struct ether_addr *source = (struct ether_addr *) eth_header->ether_shost;
    struct ether_addr *destination = (struct ether_addr *) eth_header->ether_dhost;
    int i;

    printf("src MAC: ");
    for (i = 0; i < (int) sizeof(source->ether_addr_octet) - 1; i++) {
        printf("%02x:", source->ether_addr_octet[i]);
    }
    printf("%02x\n", source->ether_addr_octet[i]);

    printf("dst MAC: ");
    for (i = 0; i < (int) sizeof(destination->ether_addr_octet) - 1; i++) {
        printf("%02x:", destination->ether_addr_octet[i]);
    }
    printf("%02x\n", destination->ether_addr_octet[i]);
}

void p_length(const struct pcap_pkthdr *h) {
    printf("frame length: %d bytes\n", h->caplen);
}

void p_ip(const struct ip *ip_header) {
    printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("dest IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

void p_port_tcp(const struct tcphdr *tcp_header) {
    printf("src port: %d\n", ntohs(tcp_header->th_sport));
    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
}

void p_port_udp(const struct udphdr *udp_header) {
    printf("src port: %d\n", ntohs(udp_header->uh_sport));
    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
}

void p_arp(const struct ether_arp *arp_header) {
    char buff[128];
    snprintf(buff, sizeof(buff), "%d.%d.%d.%d", arp_header->arp_spa[0], arp_header->arp_spa[1], arp_header->arp_spa[2],
             arp_header->arp_spa[3]);
    printf("src IP(arp): %s\n", buff);

    snprintf(buff, sizeof(buff), "%d.%d.%d.%d", arp_header->arp_tpa[0], arp_header->arp_tpa[1], arp_header->arp_tpa[2],
             arp_header->arp_tpa[3]);
    printf("dst IP(arp): %s\n", buff);

    snprintf(buff, sizeof(buff), "%02x:%02x:%02x:%02x:%02x:%02x", arp_header->arp_tha[0], arp_header->arp_tha[1],
             arp_header->arp_tha[2], arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);
    printf("src MAC(arp): %s\n", buff);

    snprintf(buff, sizeof(buff), "%02x:%02x:%02x:%02x:%02x:%02x", arp_header->arp_sha[0], arp_header->arp_sha[1],
             arp_header->arp_sha[2], arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    printf("dst MAC(arp): %s\n", buff);
}

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct ether_header *eth_header = (struct ether_header *) bytes;

    p_time((time_t) h->ts.tv_sec, h->ts.tv_usec);

    p_mac(eth_header);

    p_length(h);

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_header = (struct ether_arp *) (bytes + 14);
        p_arp(arp_header);
        printf("\n");
    }

    struct ip *ip_header = (struct ip *) (bytes + 14);
    p_ip(ip_header);

    u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

    if (ip_header->ip_p == IP_PROTOCOL_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *) (bytes + ip_len + 14);
        p_port_tcp(tcp_header);
    }

    if (ip_header->ip_p == IP_PROTOCOL_UDP) {
        struct udphdr *udp_header = (struct udphdr *) (bytes + ip_len + 14);
        p_port_udp(udp_header);
    }

    printf("\n");

    /* http://simplestcodings.blogspot.com/2010/10/create-your-own-packet-sniffer-in-c.html */
    const u_char *ch = bytes;
    u_int16_t i;
    u_char end[18];
    int space = 1;
    int count = 0;
    int row = 0;
    printf("0x%04d  ", row += 10);
    for (i = 1; i <= h->caplen; i++) {
        printf("%02x", *ch);
        if (isprint((int) *ch)) {
            end[count++] = *ch;
        } else {
            end[count++] = '.';
        }
        if (count == 8) {
            end[count++] = ' ';
        }
        if (i == h->caplen && i % 16 != 0) {
            int padding = 16 - (i % 16);
            for (int i = 0; i < padding; i++) {
                printf("   ");
            }
            end[count] = '\0';
            printf("     %s", end);
            break;
        }
        ch++;
        if (i % 16 == 0) {
            space = 1;
            end[count] = '\0';
            count = 0;
            printf("     %s\n", end);
            if (i != h->caplen) {
                printf("0x%04d  ", row += 10);
            }
            continue;
        }
        printf(" ");
        if (space % 8 == 0) {
            printf(" ");
        }
        space++;
    }
    printf("\n");
}

int main(int argc, char **argv) {
    struct Options option = def_option;
    struct bpf_program filter;
    char filter_exp[256] = "";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    bpf_u_int32 MaskIP;
    bpf_u_int32 NetIP;

    parse_args(argc, argv, &option);

    if (option.interface == NULL) {
        interface();
    }
    //debug(option);

    make_filter(&option, filter_exp);

    /*************************************************
    * Title: PROGRAMMING WITH PCAP
    * Author: Tim Carstens
    * Date: 2002
    * Code version: 1.0
    * Availability: https://www.tcpdump.org/pcap.html
    *************************************************/
    /************************************************
     This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification, are permitted provided that the following conditions are met:
        1. Redistribution must retain the above copyright notice and this list of conditions.
        2. The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.
    *************************************************/
    if (pcap_lookupnet(option.interface, &NetIP, &MaskIP, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", option.interface, errbuf);
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_live(option.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", option.interface, errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", option.interface);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &filter, filter_exp, 0, NetIP) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, option.num, handler, NULL);

    pcap_close(handle);

    /* END OF PROGRAMMING WITH PCAP */

    return EXIT_SUCCESS;
}

/**
 * Funkce vytvářející řetězcovou reprezentaci filtru pro funkci pcap_compile()
 * @param option Struktura obsahující informaci o tom jaké přepínače byly zadány
 * @param filter Ukazetel na alokované pole
 * @return Ukazetel, který bude odkazovat na výsledný řetězec filtru
 */
char *make_filter(struct Options *option, char *filter) {
    char isset = 0;
    if (option->icmp) {
        strcat(filter, "icmp");
        isset = 1;
    }

    if (option->arp) {
        if (isset) {
            strcat(filter, " or arp");
        } else {
            strcat(filter, "arp");
            isset = 1;
        }
    }

    char tmp[256];
    if (option->tcp) {
        if (isset) {
            strcat(filter, " or tcp");
            if (option->port) {
                sprintf(tmp, " port %d", option->port);
                strcat(filter, tmp);
            }
        } else {
            strcat(filter, "tcp");
            if (option->port) {
                sprintf(tmp, " port %d", option->port);
                strcat(filter, tmp);
            }
            isset = 1;
        }
    }

    if (option->udp) {
        if (isset) {
            strcat(filter, " or udp");
            if (option->port) {
                sprintf(tmp, " port %d", option->port);
                strcat(filter, tmp);
            }
        } else {
            strcat(filter, "udp");
            if (option->port) {
                sprintf(tmp, " port %d", option->port);
                strcat(filter, tmp);
            }
        }
    }

    return filter;
}

/**
 *
 */
void interface() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut1.html */
    /* https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/ */
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    for (device = alldevs; device != NULL; device = device->next) {
        printf("%s\n", device->name);
    }

    pcap_freealldevs(alldevs);
    exit(EXIT_SUCCESS);
}

/**
 *
 * @param argc
 * @param argv
 * @param option
 */
void parse_args(int argc, char **argv, struct Options *option) {
    int long_index = 0;
    int opt = 0;
    char *ptr = NULL;
    long port, number;

    while ((opt = getopt_long(argc, argv, "ip:tuIan:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                /* Stack overflow. (2020). Retrieved from https://stackoverflow.com/a/40595790 */
                if (argv[optind] != NULL && argv[optind][0] == '-') {
                    /* End of citation */
                    optind++;
                } else {
                    option->interface = argv[optind];
                }
                break;
            case 'p':
                port = strtol(optarg, &ptr, 10);
                if (strcmp(ptr, "") && port == 0) {
                    fprintf(stderr, "Please input number.\n");
                    exit(EXIT_FAILURE);
                }
                if (!BETWEEN(0, port, 65535)) {
                    fprintf(stderr, "Please input number in correct range.\n");
                    exit(EXIT_FAILURE);
                }
                option->port = (int) port;
                break;
            case 't':
                option->tcp = 1;
                break;
            case 'u':
                option->udp = 1;
                break;
            case 'I':
                option->icmp = 1;
                break;
            case 'a':
                option->arp = 1;
                break;
            case 'n':
                number = strtol(optarg, &ptr, 10);
                if (strcmp(ptr, "") && number == 0) {
                    fprintf(stderr, "Please input number.\n");
                    exit(EXIT_FAILURE);
                }
                option->num = (int) number;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }
}
