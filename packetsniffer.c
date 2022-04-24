/*****************************************************************************
 * Soubor: packetsniffer.c
 *
 * Popis: Analyzátor síťových paketů
 *
 * Autor: Tomáš Bártů, xbartu11
 *
 * Datum: 24.4.2022
 *
 *****************************************************************************
 *
 * Kód níže byl především inspirován z internetové stránky
 * http://www.tcpdump.org/. Licence je vypsána níže. Pokud daný úsek kódu byl
 * inspirován z jíné stránky, tak je licence uvedena u tohoto úseku kódu.
 *
 *****************************************************************************/

/*****************************************************************************
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 * "sniffer.c" is distributed under these terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 *
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 *
 ****************************************************************************/

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
    struct Options option = def_option; /* struktura v níž jsou prozatím uloženy defaultní data */
    struct bpf_program filter;          /* pro uložení filtru a následnou aplikaci na pcap_setfilter */
    char filter_exp[BUFSIZE] = "";      /* pro uložení výrazu, který bude aplikován na pcap_compile() */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;              /* ukazatel na používané zařízení */
    bpf_u_int32 MaskIP;                 /* maska používaného zařízení (nepoužijeme) */
    bpf_u_int32 NetIP;                  /* síťová adresa používaného zařízení */

    parse_args(argc, argv, &option); /* vyparsujeme argumenty programu do struktury Options */

    if (option.interface == NULL) {     /* pokud nebyl zadán žádný interface */
        interface();
    }
    //debug(option);

    make_filter(&option, filter_exp); /* řetězcový zápis filtru ze zadaných argumentů */

    /* zjistíme masku a síovou adresu zadaného zařízení */
    if (pcap_lookupnet(option.interface, &NetIP, &MaskIP, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", option.interface, errbuf);
        exit(EXIT_FAILURE);
    }

    /* otevřeme zařízení pro zachytáváná dat v promiskuitním módu */
    handle = pcap_open_live(option.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", option.interface, errbuf);
        exit(EXIT_FAILURE);
    }

    /* zařízení by mělo být schopno používat ethernetové rámce */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", option.interface);
        exit(EXIT_FAILURE);
    }

    /* ze zadaného výrazu vytvoříme filter */
    if (pcap_compile(handle, &filter, filter_exp, 0, NetIP) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* aplikujeme filtr na zařízení */
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, option.num, handler, NULL);     /* Zachytíme option.num počet rámce v callbacku */

    pcap_close(handle);     /* uzavřeme souboru související se zařízením */

    return EXIT_SUCCESS;
}

/**
 * Funkce pro výpis času v zadaném formátu
 * @param time Čas, který se nacházel v přijatých datech ve struktuře timeval a byl přetypován na time_t
 * @param m_second Milivteřiny, ze struktury timeval nachazející se v přijatých datech
 */
void p_time(time_t time, suseconds_t m_second) {
    char buffer[BUFSIZE];
    char z_buffer[6];                              /* časová zóna je ve formátu (+0100) plus '\0' => 6  */
    struct tm *recv_time = localtime(&time); /* pomocí localtime získáme strukturu, obsahující dny, roky, měsíce */
    // data ze struktury pomocí funkce strftime, uložíme do bufferů v požadovaném formátu
    strftime(buffer, sizeof(buffer), "%FT%T", recv_time);
    strftime(z_buffer, sizeof(z_buffer), "%z", recv_time);
    // vypíšeme čas z bufferů a přidáme k t tomu i milivteřiny
    printf("timestamp: %s.%ld%s\n", buffer, m_second, z_buffer);
}

/**
 * Funkce vypisující zdrojovou a cílovou MAC adresu z ethernetové hlavičky
 * @param eth_header Ethernetová hlavička z přijatých dat
 */
void p_mac(struct ether_header *eth_header) {
    /* Ze struktury hlavičky přetypujeme ether_shost a ether_dhost na strukturu ether_addr*/
    const struct ether_addr *source      = (struct ether_addr *) eth_header->ether_shost;
    const struct ether_addr *destination = (struct ether_addr *) eth_header->ether_dhost;
    int i;

    // vypíšeme zdrojovou MAC adresu
    printf("src MAC: ");
    for (i = 0; i < (int) sizeof(source->ether_addr_octet) - 1; i++)
        printf("%02x:", source->ether_addr_octet[i]);
    printf("%02x\n", source->ether_addr_octet[i]);

    // vypíšeme cílovou MAC adresu
    printf("dst MAC: ");
    for (i = 0; i < (int) sizeof(destination->ether_addr_octet) - 1; i++)
        printf("%02x:", destination->ether_addr_octet[i]);
    printf("%02x\n", destination->ether_addr_octet[i]);
}

/**
 * Funkce pro výpis počtu přijatých bajtů
 * @param h Hlavička přijaých dat definovaná v pcap.h
 */
void p_length(const struct pcap_pkthdr *h) {
    printf("frame length: %d bytes\n", h->caplen);
}

/**
 * Funkce pro výpis cílové a zdrojové IP adresy
 * @param ip_header Hlavička paketu
 */
void p_ip(const struct ip *ip_header) {
    /* pomocí inet_ntoa() vypíšeme adresy ze síťového prostředí (uložená v bajtech) na dekadickou tečkovou notaci */
    printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("dest IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

/**
 * Funkce pro výpis zdrojového a cílového portu ze segmentu TCP
 * @param tcp_header Hlavička TCP
 */
void p_port_tcp(const struct tcphdr *tcp_header) {
    /* Protože číslo portu je uloženo v tzv. "network byte order", tak ho převedeme na tzv. "host byte order" */
    printf("src port: %d\n", ntohs(tcp_header->th_sport));
    printf("dst port: %d\n", ntohs(tcp_header->th_dport));
}

/**
 * Funkce pro výpis zdrojového a cílového portu ze segmentu UDP
 * @param udp_header Hlavička UDP
 */
void p_port_udp(const struct udphdr *udp_header) {
    /* Protože číslo portu je uloženo v tzv. "network byte order", tak ho převedeme na tzv. "host byte order" */
    printf("src port: %d\n", ntohs(udp_header->uh_sport));
    printf("dst port: %d\n", ntohs(udp_header->uh_dport));
}

/**
 * Funkce pro výpis dat obsažených v ARP datech
 * @param arp_header Hlavička ARP
 */
void p_arp(const struct ether_arp *arp_header) {
    char buff[BUFSIZE];
    /* Ze struktury hlavičky přetypujeme arp_sha a arp_tha na strukturu ether_addr */
    const struct ether_addr *sender = (struct ether_addr *) arp_header->arp_sha;
    const struct ether_addr *target = (struct ether_addr *) arp_header->arp_tha;
    int i;

    /* vypíšeme MAC adresu odesílatele */
    printf("sender MAC: ");
    for (i = 0; i < (int) sizeof(sender->ether_addr_octet) - 1; i++)
        printf("%02x:", sender->ether_addr_octet[i]);
    printf("%02x\n", sender->ether_addr_octet[i]);

    /* vypíšeme MAC adresu cíle, pokud hledáme IP adresu tak obsah MAC adresy cíle bude ff:ff:ff:ff:ff:ff */
    printf("target MAC: ");
    for (i = 0; i < (int) sizeof(target->ether_addr_octet) - 1; i++)
        printf("%02x:", target->ether_addr_octet[i]);
    printf("%02x\n", target->ether_addr_octet[i]);

    /* vypíšeme IP adresu odoesílatele */
    snprintf(buff, sizeof(buff), "%d.%d.%d.%d", arp_header->arp_spa[0], arp_header->arp_spa[1], arp_header->arp_spa[2],
             arp_header->arp_spa[3]);
    printf("sender IP: %s\n", buff);

    /* vypíšeme hledanou IP adresu */
    snprintf(buff, sizeof(buff), "%d.%d.%d.%d", arp_header->arp_tpa[0], arp_header->arp_tpa[1], arp_header->arp_tpa[2],
             arp_header->arp_tpa[3]);
    printf("target IP: %s\n", buff);
}

/**
 * Callback funkce pcap_loop()
 * @param user Obsahuje uživatelské argumenty (nepoužíváno)
 * @param h Hlavička přijaých dat definovaná v pcap.h
 * @param bytes Ukazatel na přijaté bajty
 */
void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    /* vypíšeme timestamp */
    p_time((time_t) h->ts.tv_sec, h->ts.tv_usec);

    /* z přijatých bajtů si zjistíme ethernetovou hlavičku */
    struct ether_header *eth_header = (struct ether_header *) bytes;

    p_mac(eth_header); /* vypíšeme MAC adresy z ethernetové hlavičky */

    p_length(h);       /*vypíšeme velikost přijatých dat v bajtech */

    /* pokud je protokol, kterým jsou data v datové částí rámce zapouzdřena ARP */
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        /* tak zjistíme jeho hlavičku (posuneme ukazatel o 14 bajtů, kde 14 udáva velikost ethernetové hlaičky) */
        struct ether_arp *arp_header = (struct ether_arp *) (bytes + ETHER_HEADER_SIZE);
        p_arp(arp_header); /* vypíšeme data z datové části ethernetové hlavičky */
    }

    /* pokud je protokol, kterým jsou data v datové částí rámce zapouzdřena IP */
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        /* tak zjistíme jeho hlavičku (posuneme ukazatel o 14 bajtů, kde 14 udáva velikost ethernetové hlaičky) */
        struct ip *ip_header = (struct ip *) (bytes + ETHER_HEADER_SIZE);

        p_ip(ip_header); /* Vypíšeme IP adresy */

        /* Poněvadž IP hlavička, nemá danou pevnou délku, zjistíme její velikost z IP hlavičky a to konktrétně z
         * položky ip_hl. Tato hodnota je ale uvedena v 32-bitových slovech. Vymaskujeme hodnotu 1111 a vynásobíme
         * čtyřmi (respektive bitově posuneme hodnotu o dvě doleva)*/
        u_int ip_len = (ip_header->ip_hl & 0x0f) << 2;

        /* pokud je protokol, kterým jsou data v datové částí rámce zapouzdřena TCP */
        if (ip_header->ip_p == IP_PROTOCOL_TCP) {
            /* tak zjistíme jeho hlavičku (posuneme ukazatel o 14 bajtů + délku IP hlavičky,
             * kde 14 udáva velikost ethernetové hlaičky) */
            struct tcphdr *tcp_header = (struct tcphdr *) (bytes + ip_len + ETHER_HEADER_SIZE);
            p_port_tcp(tcp_header);
        }

        /* pokud je protokol, kterým jsou data v datové částí rámce zapouzdřena UDP */
        if (ip_header->ip_p == IP_PROTOCOL_UDP) {
            /* tak zjistíme jeho hlavičku (posuneme ukazatel o 14 bajtů + délku IP hlavičky,
             * kde 14 udáva velikost ethernetové hlaičky) */
            struct udphdr *udp_header = (struct udphdr *) (bytes + ip_len + ETHER_HEADER_SIZE);
            p_port_udp(udp_header);
        }
    }

    printf("\n");
    p_payload(bytes, h->caplen); /* Vypíšeme payload */
    printf("\n");
}

/**
 * Funkce pro výpis payloadu přijatých dat. Ve formátu:
 * 0x0000 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00     ........ ........
 * 0x0010 11 11 11 11 11 11 11 11  11 11 11 11 11 11 11 11     ........ ........
 * @param bytes Ukazatel na přijatá data
 * @param caplen Délka přijatých dat v bajtech
 */
void p_payload(const u_char *bytes, int caplen) {
    /* Vytvoříme pomocný ukazatel abychom zachovali původní ukazatel a mohli tak přistupovat k jednotlivým
     * znakům(bajtům), na které ukazuje ukazatel bytes */
    const u_char *byte = bytes;
    u_int16_t i;
    u_char end[18]; /* pro výpis znakového payloadu */
    int space = 1;  /* kde má být udělána mezera navíc */
    int count = 0;  /* počet bajtů */
    int row   = 0;  /* promměná uchovávající hodnotu řádku (pro výpis 0x0000) */
    printf("0x%04d  ", row += 10); /* hodnota řádku */
    for (i = 1; i <= caplen; i++) {
        printf("%02x", *byte);     /* jendotlivé bajty */
        if (isprint((int) *byte)) {       /* pokud se jedná o tisknutelný znak */
            end[count++] = *byte;
        } else {
            end[count++] = '.';           /* pokud se nejedná o tisknutelný znak */
        }
        if (count == 8) {                 /* pokud jsme na osmém bajtu, vložíme mezeru navíc */
            end[count++] = ' ';
        }
        /* výpis znakového payloadu pokud už jsme přečetli všechny bajty z dat, ale neskončili jsme
         * na násobku šestnácti (doplníme správný počet mezer pro správné zarovnání)*/
        if (i == caplen && i % PAYLOAD_ROW_SIZE != 0) {
            int padding = PAYLOAD_ROW_SIZE - (i % PAYLOAD_ROW_SIZE);
            for (int i = 0; i < padding; i++) {
                printf("   ");
            }
            end[count] = '\0';
            printf("      %s", end);
            break;
        }
        /* pokud skončil řádek výpisu, ale pořád jsou data k načtení, tak vypíšeme znakový payload */
        if (i % PAYLOAD_ROW_SIZE == 0) {
            space = 1;
            end[count] = '\0';
            count = 0;
            printf("     %s\n", end);
            if (i != caplen) {
                printf("0x%04d  ", row += 10);
            }
            continue;
        }
        printf(" "); /* mezera mezi bajty */
        if (space % (PAYLOAD_ROW_SIZE >> 2) == 0) {
            printf(" "); /* pokud jsme na osmém bajtu, vypíšeme mezeru navíc */
        }
        byte++;  /* posuneme se o jeden znak */
        space++; /* do pole budeme zapisovat o jednu pozici výše */
    }
}

/**
 * Funkce vytvářející řetězcovou reprezentaci filtru pro funkci pcap_compile()
 * @param option Struktura obsahující informaci o tom jaké přepínače byly zadány
 * @param filter Ukazetel na alokované pole
 * @return Ukazetel, který bude odkazovat na výsledný řetězec filtru
 */
char *make_filter(struct Options *option, char *filter) {
    char isset = 0; /* proměnná identifikující zda byl již bylo do filtru něco vloženo */
    if (option->icmp) { /* pokud ICMP */
        strcat(filter, "icmp");
        isset = 1;
    }

    if (option->arp) { /* pokud ARP */
        if (isset) {
            strcat(filter, " or arp");
        } else {
            strcat(filter, "arp");
            isset = 1;
        }
    }

    char tmp[BUFSIZE];
    if (option->tcp) { /* pokud TCP a případně pokud i port */
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

    if (option->udp) { /* pokud UDP a případně pokud i port */
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
            isset = 1;
        }
    }

    if(option->port && !option->udp && !option->tcp) { /* pokud jenom port, případně pokud port s něčím navíc */
        if (isset) {
            sprintf(tmp, " or port %d", option->port);
            strcat(filter, tmp);
        } else {
            sprintf(tmp, "port %d", option->port);
            strcat(filter, tmp);
        }
    }
    return filter;
}

/**
 * Funkce vypisující název dostupných zařízení
 */
void interface() {
    /***************************************************************************************
    * Title: How to Perform Packet Sniffing Using Libpcap with C Example Code
    * Author: HIMANSHU ARORA
    * Date: 2012
    * Code version: 1.0
    * Availability: https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
    ***************************************************************************************/
    pcap_if_t *alldevs; /* ukazatel na spojový seznam všech zařízení */
    pcap_if_t *device;  /* ukazatel na zařízení */
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) { /* zjistíme všechna dostupná zařízení */
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    /* ze spojového seznamu vypíšeme všechna jmána zařízení */
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%s\n", device->name);
    }

    pcap_freealldevs(alldevs); /* uvolníme paměť */
    /***** END OF How to Perform Packet Sniffing Using Libpcap with C Example Code *****/
    exit(EXIT_SUCCESS);
}

/**
 * Funkce parsující argumenty programu
 * @param argc Odpovídá argc ve funkci main
 * @param argv Odpovídá argv ve funkci main
 * @param option Struktura, do které jsou ukládány jednotlivé položky argumentů programu
 */
void parse_args(int argc, char **argv, struct Options *option) {
    int opt        = 0;     /* pomocná proměnná identifikující jaký argument funkce getopt_long() zpracovala */
    char *ptr      = NULL;  /* pro kontrolu, zda bylo zadáno intové číslo */
    long port, number;      /* číslo portu, počet závolání pcap_loopu */
    while ((opt = getopt_long(argc, argv, "ip:tuIan:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': /* jedná se o interface */
                /* Stack overflow. (2020). Retrieved from https://stackoverflow.com/a/40595790 */
                if (argv[optind] != NULL && argv[optind][0] == '-') {
                    /* End of citation */
                    optind++;
                } else {
                    option->interface = argv[optind];
                }
                break;
            case 'p': /* jedná se o port */
                /* kontrola zda daný řetězec je číslo a zda je ve správném rozsahu čísel portů */
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
            case 't': /* jedná se o TCP */
                option->tcp = 1;
                break;
            case 'u': /* jedná se o UDP */
                option->udp = 1;
                break;
            case 'I': /* jedná se o ICMP */
                option->icmp = 1;
                break;
            case 'a': /* jedná se o ARP */
                option->arp = 1;
                break;
            case 'n': /* jedná se o number */
                /* kontrola zda zadaný řetězec je číslo a pokud je kladné */
                number = strtol(optarg, &ptr, 10);
                if (strcmp(ptr, "") && number == 0) {
                    fprintf(stderr, "Please input number.\n");
                    exit(EXIT_FAILURE);
                }
                if ((int) number < 1)
                    exit(EXIT_FAILURE);
                option->num = (int) number;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }
}
