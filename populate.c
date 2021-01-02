#include "populate.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


uint16_t convert_endianess_16bits(uint16_t nb) {
    uint16_t result = (nb >> 8) | (nb << 8);
    return result;
}
uint32_t convert_endianess_32bits(uint32_t nb) {
    uint32_t result = ((nb >> 24))                 // move 1-st byte to 4-th byte
                      | ((nb << 24))               // move 4-th byte to 1-st byte
                      | ((nb >> 8) & 0x0000ff00)   // move 2-nd byte to 3-rd byte
                      | ((nb << 8) & 0x00ff0000);  // move 3-rd byte to 2-nd byte
    return result;
}


size_t get_data_link_protocol_header_length(Packet *packet) {
    size_t size_data_link = 0;

    switch (packet->data_link_protocol) {
        case PP_Ethernet:
            size_data_link = SIZE_ETHERNET_HEADER;
            break;
        default:
            break;
    }

    return size_data_link;
}
size_t get_network_protocol_header_length(Packet *packet) {
    size_t size_network = 0;

    switch (packet->network_protocol) {
        case PP_Ipv4:
            size_network =
                ((Ipv4Datagram *)packet->network_header)->ip_header_length * 4;
            break;
        default:
            break;
    }

    return size_network;
}
size_t get_transport_protocol_header_length(Packet *packet) {
    size_t size_transport = 0;

    switch (packet->transport_protocol) {
        case PP_Tcp:
            size_transport =
                TCP_OFFSET_VALUE((TcpSegment *)packet->transport_header) * 4;
            break;
        case PP_Udp:
            size_transport = SIZE_UDP_HEADER;
        default:
            break;
    }

    return size_transport;
}
PopulateProtocol get_network_protocol_from_code(uint16_t protocol) {
    switch (protocol) {
        case ARP_PROTOCOL:
            return PP_Arp;
        case IPV4_PROTOCOL:
            return PP_Ipv4;
        case IPV6_PROTOCOL:
            return PP_Ipv6;
        default:
            return PP_None;
    }
}
PopulateProtocol get_transport_protocol_from_code(uint8_t protocol) {
    switch (protocol) {
        case UDP_PROTOCOL:
            return PP_Udp;
        case TCP_PROTOCOL:
            return PP_Tcp;
        default:
            return PP_None;
    }
}
PopulateProtocol get_application_protocol_from_port(uint32_t port) {
    switch (port) {
        case HTTP_PORT:
            return PP_Http;
        case HTTPS_PORT:
            return PP_Tls;
        default:
            return PP_None;
    }
}
void get_http_status_code(HttpData *http_data) {
    // HTTP response 1st line: <http_version> <status_code> <status_phrase>

    char *header_str = (char *)http_data->header;
    char nb_white_spaces = 0;

    int i = 0;
    while (nb_white_spaces < 2) {
        char c = header_str[i];
        if (c == ' ') {
            nb_white_spaces++;
        }

        i++;
    }

    // we need to convert a 3 digits number's type from str to int, using the
    // ASCII table (atoi woudn't work as there isn't a '\0' after the number)
    http_data->status_code = ((int)header_str[i] - 48) * 100 +
                             ((int)header_str[i + 1] - 48) * 10 +
                             ((int)header_str[i + 2] - 48);
}
void get_http_request_method_or_status_code(HttpData *http_data) {
    // HTTP request 1st line:  <method> <uri> <http_version>
    // HTTP response 1st line: <http_version> <status_code> <status_phrase>

    char *header_str = (char *)http_data->header;
    http_data->is_response = false;

    switch (header_str[0]) {
        case 'C':
            http_data->request_method = Http_Connect;
            break;
        case 'D':
            http_data->request_method = Http_Delete;
            break;
        case 'G':
            http_data->request_method = Http_Get;
            break;
        case 'H':
            // 'HTTP' or 'HEAD'
            switch (header_str[1]) {
                case 'E':
                    http_data->request_method = Http_Head;
                    break;
                case 'T':
                    http_data->is_response = true;
                    get_http_status_code(http_data);
                    break;
                default:
                    break;
            }
            break;
        case 'O':
            http_data->request_method = Http_Options;
            break;
        case 'P':
            // 'PATCH' or 'POST' or 'PUT'
            switch (header_str[1]) {
                case 'A':
                    http_data->request_method = Http_Patch;
                    break;
                case 'O':
                    http_data->request_method = Http_Post;
                    break;
                case 'U':
                    http_data->request_method = Http_Put;
                    break;
                default:
                    break;
            }
            break;
        case 'T':
            http_data->request_method = Http_Trace;
            break;
        default:
            break;
    }
}
void find_http_header_end(HttpData *http_data) {
    // the http header ends with "\r\n\r\n"

    char *s = (char *)http_data->header;
    int i = 0;
    while (s[i] != '\r' || s[i + 1] != '\n' || s[i + 2] != '\r' ||
           s[i + 3] != '\n') {
        i++;
    }

    // +4 => "\r\n\r\n"
    http_data->data = http_data->header + i + 4;
}
void get_http_content_length(HttpData *http_data) {
    char *s = (char *)http_data->header;

    size_t i = 0;
    while (true) {
        // if the line starts with "Content-Length", break,
        // else go to the next line
        if (s[i] == 'C' && s[i + 1] == 'o' && s[i + 9] == 'e') {
            // length("Content-Length: ") = 16
            i += 16;
            break;
        }

        // go to the next line
        while (s[i] != '\n') {
            i++;
        }
        i++;
    }

    // we need to convert a n digits number's type from str to int, using the
    // ASCII table (atoi woudn't work as there isn't a '\0' after the number)
    size_t content_length = 0;
    while (s[i] != '\r') {
        content_length *= 10;
        content_length += s[i] - 48;

        i++;
    }
    http_data->content_length = content_length;
}


void populate_ethernet_frame(Packet *packet) {
    EthernetFrame *ethernet = packet->data_link_header;

    // convert the endianness of the protocol type
    ethernet->ether_protocol_type =
        convert_endianess_16bits(ethernet->ether_protocol_type);

    // add the network protocol and the header's address
    packet->network_protocol =
        get_network_protocol_from_code(ethernet->ether_protocol_type);
    packet->network_header = packet->data_link_header + SIZE_ETHERNET_HEADER;
}
void populate_ipv4_datagram(Packet *packet) {
    Ipv4Datagram *ipv4 = packet->network_header;

    // convert endianness
    ipv4->ip_total_length = convert_endianess_16bits(ipv4->ip_total_length);
    ipv4->ip_identification = convert_endianess_16bits(ipv4->ip_identification);
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
void populate_tcp_segment(Packet *packet) {
    TcpSegment *tcp = packet->transport_header;

    // convert endianness
    tcp->th_source_port = convert_endianess_16bits(tcp->th_source_port);
    tcp->th_destination_port =
        convert_endianess_16bits(tcp->th_destination_port);
    tcp->th_window = convert_endianess_16bits(tcp->th_window);
    tcp->th_checksum = convert_endianess_16bits(tcp->th_checksum);
    tcp->th_urgent_pointer = convert_endianess_16bits(tcp->th_urgent_pointer);

    tcp->th_sequence_num = convert_endianess_32bits(tcp->th_sequence_num);
    tcp->th_acknowledgement_num =
        convert_endianess_32bits(tcp->th_acknowledgement_num);

    // check if there is an application layer by comparing the length of the
    // headers with the total size of the packet, if there is an application
    // layer add the protocol and the header's address
    size_t size_data_link = get_data_link_protocol_header_length(packet);
    size_t size_network = get_network_protocol_header_length(packet);
    size_t size_transport = get_transport_protocol_header_length(packet);
    uint32_t packet_length = packet->packet_header->caplen;

    // NOTE: it's also possible to use the: ipv4->total_length to check whether
    // there is an application layer but it's not "protocol independant"
    if (packet_length > size_data_link + size_network + size_transport) {
        // NOTE: one of the ports may not be the protocol's port,
        //       that's why we have to test both
        packet->application_protocol =
            get_application_protocol_from_port(tcp->th_source_port);
        if (packet->application_protocol == PP_None) {
            packet->application_protocol =
                get_application_protocol_from_port(tcp->th_destination_port);
        }

        // *4 => words of 4 bytes (32 bits)
        packet->application_header =
            packet->transport_header + TCP_OFFSET_VALUE(tcp) * 4;
    }
}
void populate_udp_segment(Packet *packet) {
    UdpSegment *udp = packet->transport_header;

    // convert endianness
    udp->port_source = convert_endianess_16bits(udp->port_source);
    udp->port_destination = convert_endianess_16bits(udp->port_destination);
    udp->length = convert_endianess_16bits(udp->length);
    udp->checksum = convert_endianess_16bits(udp->checksum);

    // check if there is an application layer by comparing the length of the
    // headers with the total size of the packet, if there is an application
    // layer add the protocol and the header's address
    size_t size_data_link = get_data_link_protocol_header_length(packet);
    size_t size_network = get_network_protocol_header_length(packet);
    size_t size_transport = get_transport_protocol_header_length(packet);
    uint32_t packet_length = packet->packet_header->caplen;

    // NOTE: it's also possible to use the: ipv4->total_length to check whether
    // there is an application layer but it's not "protocol independant"
    if (packet_length > size_data_link + size_network + size_transport) {
        // NOTE: one of the ports may not be the protocol's port,
        //       that's why we have to test both
        packet->application_protocol =
            get_application_protocol_from_port(udp->port_source);
        if (packet->application_protocol == PP_None) {
            packet->application_protocol =
                get_application_protocol_from_port(udp->port_destination);
        }

        packet->application_header = packet->transport_header + SIZE_UDP_HEADER;
    }
}
void populate_http_data(Packet *packet) {
    // 1. copy the location of the http header before malloc a HttpData struct
    void *http_header = packet->application_header;

    // 2. malloc a http struct
    packet->application_header = malloc(sizeof(HttpData));
    HttpData *http_data = (HttpData *)packet->application_header;
    http_data->header = http_header;

    // 3. check if the header starts with "HTTP" or a request method
    get_http_request_method_or_status_code(http_data);

    // 4. get the content's length and find the end of the header
    find_http_header_end(http_data);
    if (http_data->is_response) {
        get_http_content_length(http_data);
    } else {
        http_data->content_length = 0;
    }
}
void populate_tls_data(Packet *packet) {
    // 1. copy the location of the tls header before malloc a TlsData struct
    void *tls_header = packet->application_header;

    // 2. malloc a tls struct
    packet->application_header = malloc(sizeof(TlsData));
    TlsData *tls = (TlsData *)packet->application_header;

    // 3. copy the data (only possible because tls' header is fixed size)
    (*tls) = *(TlsData *)tls_header;

    // 4. get the header's and the data's addresses
    tls->header = tls_header;
    tls->data = tls_header + SIZE_TLS_HEADER;

    // 5. convert endianness
    tls->version = convert_endianess_16bits(tls->version);
    tls->length = convert_endianess_16bits(tls->length);
}


void populate_data_link_layer(Packet *packet) {
    switch (packet->data_link_protocol) {
        case PP_Ethernet:
            populate_ethernet_frame(packet);
            break;
        default:
            break;
    }
}
void populate_network_layer(Packet *packet) {
    switch (packet->network_protocol) {
        case PP_Ipv4:
            populate_ipv4_datagram(packet);
            break;
        default:
            break;
    }
}
void populate_transport_layer(Packet *packet) {
    switch (packet->transport_protocol) {
        case PP_Tcp:
            populate_tcp_segment(packet);
            break;
        case PP_Udp:
            populate_udp_segment(packet);
            break;
        default:
            break;
    }
}
void populate_application_layer(Packet *packet) {
    switch (packet->application_protocol) {
        case PP_Http:
            populate_http_data(packet);
            break;
        case PP_Tls:
            populate_tls_data(packet);
            break;
        default:
            break;
    }
}
void populate_packet(void *packet_body, Packet *packet) {
    // populate
    populate_data_link_layer(packet);
    if (packet->network_protocol != PP_None &&
        packet->network_protocol != PP_Arp) {
        populate_network_layer(packet);
    }
    if (packet->transport_protocol != PP_None) {
        populate_transport_layer(packet);
    }
    if (packet->application_protocol != PP_None) {
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
    printf("    fragment offset: %u\n",
           convert_endianess_16bits(IP_OFFSET_VALUE(ipv4)));
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
void print_udp_segment_header(UdpSegment *udp) {
    printf("udp header:\n");

    printf("    port source: %u\n", udp->port_source);
    printf("    port destination: %u\n", udp->port_destination);
    printf("    length: %u\n", udp->length);
    printf("    checksum: %u\n", udp->checksum);
}
void print_http_data_header(HttpData *http) {
    printf("http header:\n    ");

    // print the header character per character, after every '\n', write 4
    // spaces after "\r\n\r\n", the http header is over
    size_t i = 0;
    while (http->header + i < http->data) {
        char c = *(char *)(http->header + i);
        printf("%c", c);

        if (c == '\n') {
            printf("    ");
        }

        i++;
    }

    printf("\n");
}
void print_tls_data_header(TlsData *tls) {
    printf("tls header:\n");
    printf("    content type: %u\n", tls->content_type);
    printf("    version: %u\n", tls->version);
    printf("    content length: %u\n", tls->length);
}
void print_packet_headers(Packet *packet) {
    static int i = 0;
    printf("\nPacket n°%d:\n", ++i);

    switch (packet->data_link_protocol) {
        case PP_Ethernet:
            print_ethernet_header(packet->data_link_header);
            break;
        default:
            break;
    }
    switch (packet->network_protocol) {
        case PP_Ipv4:
            print_ipv4_datagram_header(packet->network_header);
            break;
        case PP_Ipv6:
            break;
        case PP_Arp:
            break;
        default:
            break;
    }
    switch (packet->transport_protocol) {
        case PP_Tcp:
            print_tcp_segment_header(packet->transport_header);
            break;
        case PP_Udp:
            print_udp_segment_header(packet->transport_header);
            break;
        default:
            break;
    }
    switch (packet->application_protocol) {
        case PP_Http:
            print_http_data_header(packet->application_header);
            break;
        case PP_Tls:
            print_tls_data_header(packet->application_header);
            break;
        default:
            break;
    }
}
void print_data(void *start, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%c", *(char *)(start + i));
    }
    printf("\n");
}
void print_packet_data(Packet *packet) {
    void *data;
    size_t length;
    // NOTE: the data could be transported both by a transport protocol (such as
    // UDP) or by an application protocol (such as HTTP)
    switch (packet->application_protocol) {
        case PP_Http:;
            HttpData *http = (HttpData *)packet->application_header;
            data = http->data;
            length = http->content_length;
            print_data(data, length);
            return;
        case PP_Tls:;
            TlsData *tls = (TlsData *)packet->application_header;
            data = tls->data;
            length = tls->length;
            print_data(data, length);
            return;
        default:
            break;
    }
    if (packet->transport_protocol != PP_None) {
        void *data = packet->transport_header +
                     get_transport_protocol_header_length(packet);
        size_t length = packet->packet_header->caplen -
                        get_transport_protocol_header_length(packet) -
                        get_network_protocol_header_length(packet) -
                        get_data_link_protocol_header_length(packet);
        print_data(data, length);
    }
}