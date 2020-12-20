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

#define HTTP_PORT 80
#define HTTPS_PORT 443

#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* don't fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */

#define IP_OFFSET_VALUE(ip, mask) (((ip)->ip_offset_and_flags) & (mask))
#define IP_FLAG_VALUE(ip, mask) ((((ip)->ip_offset_and_flags) & (mask)) ? 1 : 0)


#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

#define TCP_OFFSET_VALUE(tcp) ((((tcp)->th_offset_flag_ns) & 0xf0) >> 4)
#define TCP_FLAG_NS_VALUE(tcp) (((tcp)->th_offset_flag_ns) & 0x01)
#define TCP_FLAG_VALUE(tcp, mask) ((((tcp)->th_flags) & (mask)) ? 1 : 0)


struct ethernet_frame {
    u_char mac_destination[ETHER_ADDR_LEN];
    u_char mac_source[ETHER_ADDR_LEN];
    u_short ether_protocol_type;
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
    u_int ip_source;
    u_int ip_destination;
} typedef Ipv4Datagram;
struct tcp_segment {
    u_short th_source_port;
    u_short th_destination_port;
    u_int th_sequence_num;
    u_int th_acknowledgement_num;
    u_char th_offset_flag_ns;
    u_char th_flags;
    u_short th_window;
    u_short th_checksum;
    u_short th_urgent_pointer;
} typedef TcpSegment;


enum data_link_protocol {
    DLP_None,
    DLP_Ethernet,
} typedef DataLinkProtocol;
enum network_protocol {
    NP_None,
    NP_Ipv4,
    NP_Ipv6,
    NP_Arp,
} typedef NetworkProtocol;
enum transport_protocol {
    TP_None,
    TP_Tcp,
    TP_Udp,
} typedef TransportProtocol;
enum application_protocol {
    AP_None,
    AP_Http,
    AP_Https,
} typedef ApplicationProtocol;

struct packet {
    DataLinkProtocol data_link_protocol;
    NetworkProtocol network_protocol;
    TransportProtocol transport_protocol;
    ApplicationProtocol application_protocol;

    void *data_link_header;
    void *network_header;
    void *transport_header;
    void *application_header;
} typedef Packet;


void populate_data_link_layer(Packet *packet);
void populate_network_layer(Packet *packet);
void populate_transport_layer(Packet *packet);
void populate_application_layer(Packet *packet);
void populate_packet(void *body, Packet *packet);


void print_ethernet_header(EthernetFrame *ethernet);
void print_ipv4_datagram_header(Ipv4Datagram *ipv4);
void print_tcp_segment_header(TcpSegment *tcp);
void print_packet_headers(Packet *packet);


void dump_memory(void *start, size_t size);
