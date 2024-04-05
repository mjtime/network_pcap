#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>

/* Ethernet header */
struct ethheader
{
    u_char ether_dhost[6]; // destination host address
    u_char ether_shost[6]; // source host address
    u_short ether_type;    // IP? ARP? RARP? etc
};

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

/* TCP Header */
struct tcpheader
{
    u_short tcp_sport; // source port
    u_short tcp_dport; // destination port
    u_int tcp_seq;     // sequence number
    u_int tcp_ack;     // acknowledgement number
    u_char tcp_offx2;  // data offset, rsvd
    u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short tcp_win; // window
    u_short tcp_sum; // checksum
    u_short tcp_urp; // urgent pointer
};

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
    char *real_data;
    // Ethernet Header: src mac/dst mac 출력
    printf("Eternet Header\n");
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    // IP Header: src ip /dst ip 출력
    printf("IP Header\n");
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP Header: src port / dst port
    printf("TCP Header\n");
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

    // 길이 구하기
    uint8_t ip_header_len = ip->iph_ihl * 4;

    uint8_t tcp_header_len = tcp->tcp_offx2 * 4;

    uint16_t ip_len = ip->iph_len;

    // data 출력
    if (ip_len - ip_header_len - tcp_header_len > 0)
    {
        real_data = (unsigned char *)(packet + sizeof(eth) + ip_header_len + tcp_header_len);
        printf("data >> \n");
        for (int i = 0; i < ip_len - ip_header_len - tcp_header_len; i++)
        {
            printf("%02X ", real_data[i]);
            if (i % 16 == 0)
            {
                printf("\n");
            }
        }
        printf("\n");
    }

    printf("\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}