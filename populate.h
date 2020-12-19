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
#define IPV4_ADDR_LEN_STR 16

#define ARP_PROTOCOL 2054
#define IPV4_PROTOCOL 2048
#define IPV6_PROTOCOL 34525
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

#define ERROR -1

#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* don't fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */

#define IP_OFFSET_VALUE(ip, mask) (((ip).ip_offset_and_flags) & (mask))
#define IP_FLAG_VALUE(ip, mask) ((((ip).ip_offset_and_flags) & (mask)) ? 1 : 0)

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
    u_char mac_destination[ETHER_ADDR_LEN];
    u_char mac_source[ETHER_ADDR_LEN];
    u_short ether_protocol_type;
    void *ethernet_body;
} typedef EthernetFrame;
///////////////////////////////////////////////////////////////////////////////
// NOTE: the order of the fields might seem weird, it's because of how the   //
//       compiler places the fields                                          //
//         0       1       2       3       4                                 //
//         0123456701234567012345670123456701234567                          //
// ip:     |ver|len|...                                                      //
// struct: |len|ver|...                                                      //
///////////////////////////////////////////////////////////////////////////////
struct ipv4_datagram {
    u_char ip_header_length : 4;
    u_char ip_version : 4;
    u_char ip_type_of_service;
    u_short ip_total_length;
    u_short ip_identification;
    u_short ip_offset_and_flags;
    u_char ip_time_to_live;
    u_char ip_protocol;
    u_short ip_checksum;
    u_int ip_source, ip_destination;
    void *ip_body;
} typedef Ipv4Datagram;


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
    char source_ip[IPV4_ADDR_LEN_STR];
    char destination_ip[IPV4_ADDR_LEN_STR];
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


EthernetFrame populate_data_link(const u_char *packet_body);
Ipv4Datagram populate_network_layer(void *ethernet_body);
void print_ethernet_header(EthernetFrame ethernet);
void print_ipv4_datagram(Ipv4Datagram ipv4);
void dump_memory(void *start, size_t size);
