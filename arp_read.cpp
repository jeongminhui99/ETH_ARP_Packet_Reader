#include <arpa/inet.h>
#include <net/ethernet.h>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <pcap.h>
#include<netinet/in.h>
using namespace std;

#define	ARPOP_REQUEST	1		/* ARP request.  */
#define	ARPOP_REPLY	2		/* ARP reply.  */

struct arphdr
{
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
    unsigned char Arpsed_mac[6]; /* Sender hardware address.  */
    unsigned char Arpsed_ip[4]; /* Sender IP address.  */
    unsigned char Arptar_mac[6]; /* Target hardware address.  */
    struct in_addr Arptar_ip;/* Target IP address.  */
};

void dump_pkt(const u_char* pkt_data, struct pcap_pkthdr* header);

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        dump_pkt(packet, header);
    }

    pcap_close(handle);

}

void dump_pkt(const u_char* pkt_data, struct pcap_pkthdr* header) {
    struct ether_header* eth_hdr = (struct ether_header*)pkt_data;
    u_int16_t eth_type = ntohs(eth_hdr->ether_type);

    //if type is not IP, return function
    if (eth_type != ETHERTYPE_ARP) return; // 0x0806

    struct arphdr* arp_hdr = (struct arphdr*)(pkt_data + sizeof(ether_header));


    printf("\nARP Packet Info====================================\n");

    //print pkt length
    printf("%u bytes captured\n", header->caplen);

    //print mac addr
    u_int8_t* dst_mac = eth_hdr->ether_dhost;
    u_int8_t* src_mac = eth_hdr->ether_shost;

    printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    u_int8_t* d_mac = arp_hdr->Arpsed_mac;
    u_int8_t* sr_mac = arp_hdr->Arptar_mac;
    u_int8_t* s_ip = arp_hdr->Arpsed_ip;

    //print request || reply
    if (ntohs(arp_hdr->ar_op) == ARPOP_REQUEST) { //#define	ARPOP_REQUEST	1
        printf(" \n******* request ******* \n");
        printf("Hardware Type : %02x\n", ntohs(arp_hdr->ar_hrd));
        printf("Protocol Type : %02x\n", ntohs(arp_hdr->ar_pro));
        printf("Hardware size : %02x\n", (arp_hdr->ar_hln));
        printf("Protocol size : %02x\n", (arp_hdr->ar_pln));
        printf("Opcode : %d\n", ntohs(arp_hdr->ar_op));
        printf("Sender MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
            d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);
        printf("Sender IP : %d.%d.%d.%d\n ", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);
        printf("\n");
        printf("Target MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_hdr->Arptar_mac[0], arp_hdr->Arptar_mac[1], arp_hdr->Arptar_mac[2], arp_hdr->Arptar_mac[3], arp_hdr->Arptar_mac[4], arp_hdr->Arptar_mac[5]);
        printf("Target IP : %s\n ", inet_ntoa(arp_hdr->Arptar_ip));
        printf("\n");
    }
    else if (ntohs(arp_hdr->ar_op) == ARPOP_REPLY) { //#define  ARPOP_REPLY	2
        printf(" ********  reply  ******** \n");
        printf("Sender IP : %d.%d.%d.%d\n ", s_ip[0], s_ip[1], s_ip[2], s_ip[3]);
        printf("Sender MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_hdr->Arpsed_mac[0], arp_hdr->Arpsed_mac[1], arp_hdr->Arpsed_mac[2], arp_hdr->Arpsed_mac[3], arp_hdr->Arpsed_mac[4], arp_hdr->Arpsed_mac[5]);
        printf("Target IP : %s\n ", inet_ntoa(arp_hdr->Arptar_ip));
        printf("Target MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
            arp_hdr->Arptar_mac[0], arp_hdr->Arptar_mac[1], arp_hdr->Arptar_mac[2], arp_hdr->Arptar_mac[3], arp_hdr->Arptar_mac[4], arp_hdr->Arptar_mac[5]);
        printf("\n");
    }


    //print payload
    u_int32_t payload_len = header->caplen - sizeof(ether_header) - sizeof(arp_hdr);
    u_int32_t max = payload_len >= 16 ? 16 : payload_len;
    const u_char* pkt_payload = pkt_data + sizeof(ether_header) + sizeof(arp_hdr);
    printf("Payload : ");

    if (!payload_len) {
        printf("No payload\n");
    }
    else {
        for (int i = 0; i < max; i++) printf("%02x ", *(pkt_payload + i));
        printf("\n");
    }
}