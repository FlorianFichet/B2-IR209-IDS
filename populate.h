#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>


#define SIZE_MAC_ADDRESS 6
#define SIZE_IPV4_ADDRESS 4
#define SIZE_ETHERNET_HEADER 14


#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN_STR 18
#define IP_ADDR_LEN_STR 16

#define ARP 2054
#define IPV4 2048
#define IPV6 34525
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

#define ERROR -1

#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* don't fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)


struct ethernet_frame {
    uint8_t mac_destination[SIZE_MAC_ADDRESS];
    uint8_t mac_source[SIZE_MAC_ADDRESS];
    uint16_t protocol_type;
    void *ethernet_body;
} typedef EthernetFrame;
///////////////////////////////////////////////////////////////////////////////
// NOTE: the order of the fields might seem weird, it's because of endianess //
//         0       1       2       3       4                                 //
//         0123456701234567012345670123456701234567                          //
// ip:     |ver|len|...                                                      //
// struct: |len|ver|...                                                      //
///////////////////////////////////////////////////////////////////////////////
struct ipv4_datagram {
    uint8_t header_length : 4;  // words of 32 bits
    uint8_t ip_version : 4;
    uint8_t type_of_service;
    uint16_t total_length;  // words of 32 bits
    uint16_t identification;
    uint8_t flag_more_fragments : 1;
    uint8_t flag_dont_fragment : 1;
    uint8_t flag_reserved : 1;
    uint16_t fragment_offset : 13;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t ip_source;
    uint32_t ip_destination;
    void *ip_body;
} typedef Ipv4Datagram;


EthernetFrame populate_data_link(const u_char *packet_body);
Ipv4Datagram populate_network_layer(void *ethernet_body);
void print_ethernet_header(EthernetFrame ethernet);
void print_ipv4_datagram(Ipv4Datagram ipv4);
void dump_memory(void *start, size_t size);


/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
    u_char th_flags;
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

struct custom_udp {
    int source_port;
    int destination_port;
    unsigned char *data;
} typedef UDP_Packet;

struct custom_tcp {
    int source_port;
    int destination_port;
    int sequence_number;
    int ack_number;
    int th_flag;
    unsigned char *data;
    int data_length;
} typedef TCP_Segment;

struct custom_ip {
    char source_ip[IP_ADDR_LEN_STR];
    char destination_ip[IP_ADDR_LEN_STR];
    TCP_Segment data;
} typedef IP_Packet;

struct custom_ethernet {
    char source_mac[ETHER_ADDR_LEN_STR];
    char destination_mac[ETHER_ADDR_LEN_STR];
    int ethernet_type;
    int frame_size;
    IP_Packet data;
} typedef ETHER_Frame;

int populate_packet_ds(const struct pcap_pkthdr *header, const u_char *packet,
                       ETHER_Frame *frame);
void print_payload(int payload_length, unsigned char *payload);
