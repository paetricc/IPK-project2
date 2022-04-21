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

int main(int argc, char **argv) {
    struct Options option = def_option;

    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    parse_args(argc, argv, &option);
    debug(option);
    return EXIT_SUCCESS;
}

void parse_args(int argc,char **argv, struct Options *option) {
    int long_index = 0;
    int opt = 0;

    while((opt = getopt_long(argc, argv, "ip:tuIan:", long_options, &long_index)) != -1 ) {
        switch (opt) {
            case 'i':
                if (argv[optind][0] == '-') {
                    optind++;
                } else {
                    option->interface = argv[optind];
                }
                break;
            case 'p':
                option->port = atoi(optarg);
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
                option->num = atoi(optarg);
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }
}
