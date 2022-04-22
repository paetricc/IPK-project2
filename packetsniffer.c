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

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char *packet){
    static int i = 1;
    printf("Paket cislo %d\n", i++);
}

int main(int argc, char **argv) {
    struct Options option = def_option;
    struct bpf_program filter;
    struct pcap_pkthdr header;
    char filter_exp[256] = "";
    pcap_t *handle = NULL;
    bpf_u_int32 MaskIP;
    bpf_u_int32 NetIP;

    parse_args(argc, argv, &option);

    if (option.interface == NULL) {
        interface();
    }
    //debug(option);

    make_filter(&option, filter_exp);

    char errbuf[PCAP_ERRBUF_SIZE];

    /* https://www.tcpdump.org/pcap.html */
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

    pcap_loop(handle, option.num, callback, NULL);

    pcap_close(handle);

    return EXIT_SUCCESS;
}

char* make_filter(struct Options *option, char *filter) {
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

void interface(){
    pcap_if_t *alldevs;
    pcap_if_t *device;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut1.html */
    /* https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/ */
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    for (device = alldevs; device != NULL; device = device->next) {
        printf("%d. %s", ++i, device->name);
        if (device->description) {
            printf(" (%s)\n", device->description);
        } else {
            printf(" (No description available)\n");
        }
    }

    pcap_freealldevs(alldevs);
    exit(EXIT_SUCCESS);
}

void parse_args(int argc,char **argv, struct Options *option) {
    int long_index = 0;
    int opt = 0;
    char *ptr = NULL;
    long port, number;

    while((opt = getopt_long(argc, argv, "ip:tuIan:", long_options, &long_index)) != -1 ) {
        switch (opt) {
            case 'i':
                /* https://stackoverflow.com/questions/40594208/getopt-long-option-with-optional-argument */
                if (argv[optind] != NULL && argv[optind][0] == '-') {
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
                option->port = (int)port;
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
                option->num = (int)number;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }
}
