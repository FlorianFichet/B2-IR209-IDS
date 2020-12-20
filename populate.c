#include "populate.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


uint16_t convert_endianess_16bits(uint16_t nb) {
    uint16_t result = ((nb >> 8)) | ((nb << 8));
    return result;
}
uint32_t convert_endianess_32bits(uint32_t nb) {
    uint32_t result = ((nb >> 24))                // move 1-st byte to 4-th byte
                      | ((nb << 24))              // move 4-th byte to 1-st byte
                      | ((nb >> 8) & 0x0000ff00)  // move 2-nd byte to 3-rd byte
                      |
                      ((nb << 8) & 0x00ff0000);  // move 3-rd byte to 2-nd byte
    return result;
}


NetworkProtocol get_network_protocol_from_code(uint16_t protocol) {
    switch (protocol) {
        case ARP_PROTOCOL:
            return NP_Arp;
        case IPV4_PROTOCOL:
            return NP_Ipv4;
        case IPV6_PROTOCOL:
            return NP_Ipv6;

        default:
            return NP_None;
    }
}
TransportProtocol get_transport_protocol_from_code(uint8_t protocol) {
    switch (protocol) {
        case UDP_PROTOCOL:
            return TP_Udp;
        case TCP_PROTOCOL:
            return TP_Tcp;

        default:
            return TP_None;
    }
}
ApplicationProtocol get_application_protocol_from_port(uint32_t port) {
    switch (port) {
        case HTTP_PORT:
            return AP_Http;
        case HTTPS_PORT:
            return AP_Https;

        default:
            return AP_None;
    }
}


void populate_data_link_layer(Packet *packet) {
    if (packet->data_link_protocol == DLP_Ethernet) {
        EthernetFrame *ethernet = packet->data_link_header;

        // convert the endianness of the protocol type
        ethernet->ether_protocol_type =
            convert_endianess_16bits(ethernet->ether_protocol_type);

        // add the network protocol and the header's address
        packet->network_protocol =
            get_network_protocol_from_code(ethernet->ether_protocol_type);
        packet->network_header =
            packet->data_link_header + SIZE_ETHERNET_HEADER;
    }
}
void populate_network_layer(Packet *packet) {
    if (packet->network_protocol == NP_Ipv4) {
        Ipv4Datagram *ipv4 = packet->network_header;

        // convert endianness
        ipv4->ip_total_length = convert_endianess_16bits(ipv4->ip_total_length);
        ipv4->ip_identification =
            convert_endianess_16bits(ipv4->ip_identification);
        ipv4->ip_checksum = convert_endianess_16bits(ipv4->ip_checksum);

        ipv4->ip_source = convert_endianess_32bits(ipv4->ip_source);
        ipv4->ip_destination = convert_endianess_32bits(ipv4->ip_destination);

        // add the transport protocol and the header's address
        packet->transport_protocol =
            get_transport_protocol_from_code(ipv4->ip_protocol);
        // *4 => words of 4 bytes (32 bits)
        packet->transport_header =
            packet->network_header + ipv4->ip_header_length * 4;
    }
}
void populate_transport_layer(Packet *packet) {
    if (packet->transport_protocol == TP_Tcp) {
        TcpSegment *tcp = packet->transport_header;

        // convert endianness
        tcp->th_source_port = convert_endianess_16bits(tcp->th_source_port);
        tcp->th_destination_port =
            convert_endianess_16bits(tcp->th_destination_port);
        tcp->th_window = convert_endianess_16bits(tcp->th_window);
        tcp->th_checksum = convert_endianess_16bits(tcp->th_checksum);
        tcp->th_urgent_pointer =
            convert_endianess_16bits(tcp->th_urgent_pointer);

        tcp->th_sequence_num = convert_endianess_32bits(tcp->th_sequence_num);
        tcp->th_acknowledgement_num =
            convert_endianess_32bits(tcp->th_acknowledgement_num);

        // add the application protocol and the header's address

        // NOTE: the server's port may not be the protocol's port,
        //       that's why we have to test both
        packet->application_protocol =
            get_application_protocol_from_port(tcp->th_source_port);

        if (packet->application_protocol == AP_None) {
            packet->application_protocol =
                get_application_protocol_from_port(tcp->th_destination_port);
        }

        // *4 => words of 4 bytes (32 bits)
        packet->application_header =
            packet->transport_header + TCP_OFFSET_VALUE(tcp) * 4;
    }
}
void populate_application_layer(Packet *packet) {}
void populate_packet(void *packet_body, Packet *packet) {
    // initialize
    packet->data_link_protocol = DLP_Ethernet;
    packet->network_protocol = NP_None;
    packet->transport_protocol = TP_None;
    packet->application_protocol = AP_None;

    packet->data_link_header = packet_body;
    packet->network_header = NULL;
    packet->transport_header = NULL;
    packet->application_header = NULL;

    // populate
    populate_data_link_layer(packet);
    if (packet->network_protocol != NP_None &&
        packet->network_protocol != NP_Arp) {
        populate_network_layer(packet);
    }
    if (packet->transport_protocol != TP_None) {
        populate_transport_layer(packet);
    }
    if (packet->application_protocol != AP_None) {
        populate_application_layer(packet);
    }
}


void get_ethernet_protocol_name(uint16_t protocol_type, char *protocol_name) {
    switch (protocol_type) {
        case IPV4_PROTOCOL:
            strcpy(protocol_name, "Internet Protocol version 4 (IPv4)");
            break;
        case IPV6_PROTOCOL:
            strcpy(protocol_name, "Internet Protocol version 6 (IPv6)");
            break;
        case ARP_PROTOCOL:
            strcpy(protocol_name, "Address Resolution Protocol (ARP)");
            break;

        default:
            break;
    }
}
void get_internet_protocol_name(u_char protocol_type, char *protocol_name) {
    switch (protocol_type) {
        case 0:
            strcpy(protocol_name, "IPv6 Hop-by-Hop Option (HOPOPT)");
            break;
        case 1:
            strcpy(protocol_name, "Internet Control Message (ICMP)");
            break;
        case 6:
            strcpy(protocol_name, "Transmission Control (TCP)");
            break;
        case 17:
            strcpy(protocol_name, "User Datagram (UDP)");
            break;

        default:
            break;
    }
}
char *get_ipv4_address_string(u_int ip, char *s) {
    // an array of int to prevent overflow
    u_int bytes[4];
    bytes[0] = ip % 256;
    bytes[1] = (ip >> 8) % 256;
    bytes[2] = (ip >> 16) % 256;
    bytes[3] = (ip >> 24) % 256;

    snprintf(s, IPV4_ADDR_LEN_STR, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1],
             bytes[0]);
    return s;
}


void print_ethernet_header(EthernetFrame *ethernet) {
    char protocol_name[50] = "unknown protocol";
    get_ethernet_protocol_name(ethernet->ether_protocol_type, protocol_name);

    printf("ethernet header:\n");

    // display the mac addresses
    printf("    mac destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet->mac_destination[0], ethernet->mac_destination[1],
           ethernet->mac_destination[2], ethernet->mac_destination[3],
           ethernet->mac_destination[4], ethernet->mac_destination[5]);
    printf("    mac source: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet->mac_source[0], ethernet->mac_source[1],
           ethernet->mac_source[2], ethernet->mac_source[3],
           ethernet->mac_source[4], ethernet->mac_source[5]);

    // display the network protocol
    printf("    protocol type: %u", ethernet->ether_protocol_type);
    printf(" -- %s\n", protocol_name);
}
void print_ipv4_datagram_header(Ipv4Datagram *ipv4) {
    char ipv4_str[IPV4_ADDR_LEN_STR];
    char protocol_name[50] = "unknown protocol";
    get_internet_protocol_name(ipv4->ip_protocol, protocol_name);

    printf("ipv4 header:\n");

    printf("    ip version: %u\n", ipv4->ip_version);
    printf("    header length: %u\n", ipv4->ip_header_length);
    printf("    type of service: %u\n", ipv4->ip_type_of_service);
    printf("    total length: %u\n", ipv4->ip_total_length);
    printf("    identification: %u\n", ipv4->ip_identification);
    printf("    flag reserved: %u\n", IP_FLAG_VALUE(ipv4, IP_RF));
    printf("    flag don't fragment: %u\n", IP_FLAG_VALUE(ipv4, IP_DF));
    printf("    flag more fragments: %u\n", IP_FLAG_VALUE(ipv4, IP_MF));
    printf("    fragment offset: %u\n", IP_OFFSET_VALUE(ipv4, IP_OFFMASK));
    printf("    time to live: %u\n", ipv4->ip_time_to_live);
    printf("    protocol: %u -- %s\n", ipv4->ip_protocol, protocol_name);
    printf("    header checksum: %u\n", ipv4->ip_checksum);
    printf("    ip source: %s\n",
           get_ipv4_address_string(ipv4->ip_source, ipv4_str));
    printf("    ip destination: %s\n",
           get_ipv4_address_string(ipv4->ip_destination, ipv4_str));
}
void print_tcp_segment_header(TcpSegment *tcp) {
    printf("tcp header:\n");

    printf("    source port: %u\n", tcp->th_source_port);
    printf("    destination port: %u\n", tcp->th_destination_port);
    printf("    sequence number: %u\n", tcp->th_sequence_num);
    printf("    acknowledgement number: %u\n", tcp->th_acknowledgement_num);
    printf("    offset: %u\n", TCP_OFFSET_VALUE(tcp));
    printf("    flag NS: %u\n", TCP_FLAG_NS_VALUE(tcp));
    printf("    flag CWR: %u\n", TCP_FLAG_VALUE(tcp, TH_CWR));
    printf("    flag ECE: %u\n", TCP_FLAG_VALUE(tcp, TH_ECE));
    printf("    flag URG: %u\n", TCP_FLAG_VALUE(tcp, TH_URG));
    printf("    flag ACK: %u\n", TCP_FLAG_VALUE(tcp, TH_ACK));
    printf("    flag PUSH: %u\n", TCP_FLAG_VALUE(tcp, TH_PUSH));
    printf("    flag RST: %u\n", TCP_FLAG_VALUE(tcp, TH_RST));
    printf("    flag SYN: %u\n", TCP_FLAG_VALUE(tcp, TH_SYN));
    printf("    flag FIN: %u\n", TCP_FLAG_VALUE(tcp, TH_FIN));
    printf("    window: %u\n", tcp->th_window);
    printf("    checksum: %u\n", tcp->th_checksum);
    printf("    urgent pointer: %u\n", tcp->th_urgent_pointer);
}
void print_packet_headers(Packet *packet) {
    static int i = 0;
    printf("Packet n°%d:\n", ++i);

    switch (packet->data_link_protocol) {
        case DLP_Ethernet:
            print_ethernet_header(packet->data_link_header);
            break;
        default:
            break;
    }
    switch (packet->network_protocol) {
        case NP_Ipv4:
            print_ipv4_datagram_header(packet->network_header);
            break;
        case NP_Ipv6:
            break;
        case NP_Arp:
            break;
        default:
            break;
    }
    switch (packet->transport_protocol) {
        case TP_Tcp:
            print_tcp_segment_header(packet->transport_header);
            break;
        case TP_Udp:
            break;
        default:
            break;
    }
    switch (packet->application_protocol) {
        case AP_Http:
            break;
        case AP_Https:
            break;
        default:
            break;
    }
}


void dump_memory(void *start, size_t size) {
    int i = 0;
    while (i < size) {
        if (i % 16 == 15) {
            printf("\n");
        }
        printf("%02x ", *(uint8_t *)(start + i));
        i++;
    }
    printf("\n");
}
