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


EthernetFrame populate_data_link(const u_char *packet_body) {
    EthernetFrame *ethernet = (EthernetFrame *)packet_body;

    // convert the endianness of the protocol type
    ethernet->ether_protocol_type =
        convert_endianess_16bits(ethernet->ether_protocol_type);

    // get the ethernet frame's body
    ethernet->ethernet_body = (void *)ethernet + SIZE_ETHERNET_HEADER;

    return *ethernet;
}
Ipv4Datagram populate_network_layer(void *ethernet_body) {
    Ipv4Datagram *ipv4 = ethernet_body;

    // convert endianness
    ipv4->ip_total_length = convert_endianess_16bits(ipv4->ip_total_length);
    ipv4->ip_identification = convert_endianess_16bits(ipv4->ip_identification);
    ipv4->ip_checksum = convert_endianess_16bits(ipv4->ip_checksum);

    ipv4->ip_source = convert_endianess_32bits(ipv4->ip_source);
    ipv4->ip_destination = convert_endianess_32bits(ipv4->ip_destination);

    // *4 => coded on 4 bytes (32 bits)
    ipv4->ip_body = (void *)ipv4 + ipv4->ip_header_length * 4;

    return *ipv4;
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
void print_ethernet_header(EthernetFrame ethernet) {
    char protocol_name[50] = "unknown protocol";
    get_ethernet_protocol_name(ethernet.ether_protocol_type, protocol_name);

    printf("ethernet header:\n");

    // display the mac addresses
    printf("    mac destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet.mac_destination[0], ethernet.mac_destination[1],
           ethernet.mac_destination[2], ethernet.mac_destination[3],
           ethernet.mac_destination[4], ethernet.mac_destination[5]);
    printf("    mac source: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet.mac_source[0], ethernet.mac_source[1],
           ethernet.mac_source[2], ethernet.mac_source[3],
           ethernet.mac_source[4], ethernet.mac_source[5]);

    // display the network protocol
    printf("    protocol type: %u", ethernet.ether_protocol_type);
    printf(" -- %s\n", protocol_name);
}
void print_ipv4_datagram(Ipv4Datagram ipv4) {
    char ipv4_str[IPV4_ADDR_LEN_STR];
    char protocol_name[50] = "unknown protocol";
    get_internet_protocol_name(ipv4.ip_protocol, protocol_name);

    printf("ipv4 header:\n");

    printf("    ip version: %u\n", ipv4.ip_version);
    printf("    header length: %u\n", ipv4.ip_header_length);
    printf("    type of service: %u\n", ipv4.ip_type_of_service);
    printf("    total length: %u\n", ipv4.ip_total_length);
    printf("    identification: %u\n", ipv4.ip_identification);
    printf("    flag reserved: %u\n", IP_FLAG_VALUE(ipv4, IP_RF));
    printf("    flag don't fragment: %u\n", IP_FLAG_VALUE(ipv4, IP_DF));
    printf("    flag more fragments: %u\n", IP_FLAG_VALUE(ipv4, IP_MF));
    printf("    fragment offset: %u\n", IP_OFFSET_VALUE(ipv4, IP_OFFMASK));
    printf("    time to live: %u\n", ipv4.ip_time_to_live);
    printf("    protocol: %u -- %s\n", ipv4.ip_protocol, protocol_name);
    printf("    header checksum: %u\n", ipv4.ip_checksum);
    printf("    ip source: %s\n",
           get_ipv4_address_string(ipv4.ip_source, ipv4_str));
    printf("    ip destination: %s\n",
           get_ipv4_address_string(ipv4.ip_destination, ipv4_str));
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


// int populate_packet_ds(const struct pcap_pkthdr *header, const u_char
// *packet,
//                        ETHER_Frame *custom_frame) {
//     const EthernetFrame *ethernet; /* The ethernet header */
//     const Ipv4Datagram *ip;        /* The IP header */
//     const struct sniff_tcp *tcp;   /* The TCP header */
//     unsigned char *payload;        /* Packet payload */

//     u_int size_ip;
//     u_int size_tcp;

//     ethernet = (EthernetFrame *)(packet);
//     // ETHER_Frame custom_frame;
//     char src_mac_address[ETHER_ADDR_LEN_STR];
//     char dst_mac_address[ETHER_ADDR_LEN_STR];
//     custom_frame->frame_size = header->caplen;
//     // Convert unsigned char MAC to string MAC
//     for (int x = 0; x < 6; x++) {
//         snprintf(src_mac_address + (x * 2), ETHER_ADDR_LEN_STR, "%02x",
//                  ethernet->mac_source[x]);
//         snprintf(dst_mac_address + (x * 2), ETHER_ADDR_LEN_STR, "%02x",
//                  ethernet->mac_destination[x]);
//     }

//     strcpy(custom_frame->source_mac, src_mac_address);
//     strcpy(custom_frame->destination_mac, dst_mac_address);

//     if (ntohs(ethernet->ether_protocol_type) == ETHERTYPE_ARP) {
//         custom_frame->ethernet_type = ARP_PROTOCOL;
//         printf("\nARP packet: %d\n", custom_frame->ethernet_type);
//     }

//     if (ntohs(ethernet->ether_protocol_type) == ETHERTYPE_IP) {
//         custom_frame->ethernet_type = IPV4_PROTOCOL;
//         printf("\nIPV4 packet: %d\n", custom_frame->ethernet_type);

//         ip = (Ipv4Datagram *)(packet + SIZE_ETHERNET);
//         IP_Packet custom_packet;
//         char src_ip[IPV4_ADDR_LEN_STR];
//         char dst_ip[IPV4_ADDR_LEN_STR];
//         generate_ip(ip->ip_source.s_addr, src_ip);
//         generate_ip(ip->ip_destination.s_addr, dst_ip);

//         strcpy(custom_packet.source_ip, src_ip);
//         strcpy(custom_packet.destination_ip, dst_ip);

//         size_ip = IP_HL(ip) * 4;

//         if (size_ip < 20) {
//             printf("   * Invalid IP header length: %u bytes\n", size_ip);
//             return ERROR;
//         }

//         if ((int)ip->ip_protocol == UDP_PROTOCOL) {
//             printf("\nUDP Handling\n");
//         }
//         if ((int)ip->ip_protocol == TCP_PROTOCOL) {
//             printf("\nTCP Handling\n");
//             tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
//             TCP_Segment custom_segment;

//             size_tcp = TH_OFF(tcp) * 4;

//             if (size_tcp < 20) {
//                 printf("   * Invalid TCP header length: %u bytes\n",
//                 size_tcp); return ERROR;
//             }
//             payload = (u_char *)(packet + SIZE_ETHERNET + size_ip +
//             size_tcp);

//             int payload_length =
//                 (header->caplen) - SIZE_ETHERNET - size_ip - size_tcp;
//             custom_segment.source_port = ntohs(tcp->th_sport);
//             custom_segment.destination_port = ntohs(tcp->th_dport);
//             custom_segment.th_flag = (int)tcp->th_flags;
//             custom_segment.sequence_number = tcp->th_seq;
//             custom_segment.data = payload;
//             custom_segment.data_length = payload_length;

//             custom_packet.data = custom_segment;
//             custom_frame->data = custom_packet;
//         }
//     }

//     return 0;
// }
