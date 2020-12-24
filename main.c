#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>

#include "populate.h"
#include "rules.h"


#define SNIFFER_ERROR_HANDLE_NOT_CREATED 1
#define SNIFFER_ERROR_HANDLE_NOT_ACTIVATED 2
#define FILE_NOT_OPENED_ERROR 3


struct ids_arguments {
    bool print_help;
    bool print_packet_headers;
    char *device;
    char *rules_file_name;
    int total_packet_count;
} typedef IdsArguments;


struct user_args_packet_handler {
    bool print_packet_headers;
    int nb_rules;
    Rule *rules;
} typedef UserArgsPacketHandler;


void write_syslog(char *message) {
    // NOTE: options are coded on an int
    // LOG_CONS   = 0x02 = log on the console if errors in sending
    // LOG_PID    = 0x01 = log the pid with each message
    // LOG_NDELAY = 0x08 = don't delay open
    openlog("Ids", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    syslog(LOG_ALERT, message);
    closelog();
}


IdsArguments parse_arguments(int argc, char *argv[]) {
    IdsArguments arguments = {
        .print_help = false,
        .print_packet_headers = false,
        .device = "eth0",
        .rules_file_name = "/etc/ids/ids.rules",
        .total_packet_count = 1,
    };

    int i = 0;
    while (i < argc) {
        char *s = argv[i];

        if (strcmp(s, "-h") == 0 || strcmp(s, "--help") == 0) {
            arguments.print_help = true;
        } else if (strcmp(s, "-p") == 0 || strcmp(s, "--print-headers") == 0) {
            arguments.print_packet_headers = true;
        } else if (strcmp(s, "-d") == 0 || strcmp(s, "--device") == 0) {
            arguments.device = argv[++i];
        } else if (strcmp(s, "-r") == 0 || strcmp(s, "--rules") == 0) {
            arguments.rules_file_name = argv[++i];
        } else if (strcmp(s, "-n") == 0 || strcmp(s, "--nb-packets") == 0) {
            arguments.total_packet_count = atoi(argv[++i]);
        }

        i++;
    }

    return arguments;
}
void print_help() {
    printf("Usage: ids [options]\n");
    printf(
        "Option          Long Option               "
        "Meaning\n");
    printf(
        "-h              --help                    "
        "Display this help and exit\n");
    printf(
        "-p              --print-headers           "
        "Print the headers of every protocol\n");
    printf(
        "                                          "
        "  in the intercepted packets\n");
    printf(
        "-d <interface>  --device <interface>      "
        "Network interface to spy on\n");
    printf(
        "-r <rule_file>  --rules <rule_file>       "
        "File that contains the rules\n");
    printf(
        "-n <nb_packets> --nb-packets <nb_packets> "
        "Number of packets to analyse\n");
}


// get the activated handle into 'handle', it is opened on 'device',
// returns 0 on success
int get_activated_handle(pcap_t **handle_ptr, char device[],
                         char error_buffer[]) {
    // 1. create the handle
    (*handle_ptr) = pcap_create(device, error_buffer);
    if ((*handle_ptr) == NULL) {
        pcap_close(*handle_ptr);
        return SNIFFER_ERROR_HANDLE_NOT_CREATED;
    }

    // 2. set timeout (in ms)
    pcap_set_timeout(*handle_ptr, 10);

    // 3. activate the handle
    if (pcap_activate(*handle_ptr) != 0) {
        return SNIFFER_ERROR_HANDLE_NOT_ACTIVATED;
    }

    return 0;
}


void get_rule_protocols_from_packet(RuleProtocol *protocols, Packet *packet) {
    switch (packet->data_link_protocol) {
        case DLP_Ethernet:
            protocols[0] = Ethernet;
            break;
        default:
            protocols[0] = No_Protocol;
            break;
    }
    switch (packet->network_protocol) {
        case NP_Ipv4:
            protocols[1] = Ipv4;
            break;
        case NP_Ipv6:
            protocols[1] = Ipv6;
            break;
        default:
            protocols[1] = No_Protocol;
            break;
    }
    switch (packet->transport_protocol) {
        case TP_Tcp:
            protocols[2] = Tcp;
            break;
        case TP_Udp:
            protocols[2] = Udp;
            break;
        default:
            protocols[2] = No_Protocol;
            break;
    }
    switch (packet->application_protocol) {
        case AP_Http:
            protocols[3] = Http;
            break;
        default:
            protocols[3] = No_Protocol;
            break;
    }
}
void get_ipv4_from_packet(uint32_t *addresses, Packet *packet) {
    Ipv4Datagram *ipv4_header = (Ipv4Datagram *)packet->network_header;
    addresses[0] = ipv4_header->ip_source;
    addresses[1] = ipv4_header->ip_destination;
}
void get_ports_from_packet(uint16_t *ports, Packet *packet) {
    // NOTE: the semicolon ';' after the 'case:' might seem unecessary but we
    // need it because of the C standard: "a label can only be part of a
    // statement and a declaration is not a statement". That's why we need an
    // empty statement.

    switch (packet->transport_protocol) {
        case TP_Tcp:;
            TcpSegment *tcp_header = (TcpSegment *)packet->transport_header;
            ports[0] = tcp_header->th_source_port;
            ports[1] = tcp_header->th_destination_port;
            break;
        default:
            break;
    }
}
bool check_protocol_match(Rule *rule, RuleProtocol *protocols) {
    bool protocols_match = false;

    for (size_t i = 0; i < 4; i++) {
        if (rule->protocol == protocols[i]) {
            protocols_match = true;
            break;
        }
    }

    return protocols_match;
}
bool check_ipv4_match(RuleIpv4 *addresses, int nb_rules_ip, uint32_t ip) {
    bool ips_match = false;

    for (size_t i = 0; i < nb_rules_ip; i++) {
        // NOTE: no break because we have to do all the list in case there
        // is a negation
        if (addresses[i].ip == -1) {  // -1 => any
            // !negation => match
            ips_match = !addresses[i].negation;
        } else {
            // e.g. 255.255.255.255/24
            //  a. inverse_netmask = 8
            //  b. host_ip = 255.255.255.255 % (1 << 8)
            //             = 255.255.255.255 % 256
            //             =   0.  0.  0.255
            //  c. network_ip = 255.255.255.0
            uint32_t inverse_netmask = 32 - addresses[i].netmask;
            uint32_t host_ip = ip % (1 << inverse_netmask);
            uint32_t network_ip = ip - host_ip;
            if (network_ip == addresses[i].ip) {
                ips_match = !addresses[i].negation;
            }
        }
    }

    return ips_match;
}
bool check_port_match(RulePort *ports, int nb_rules_port, uint16_t port) {
    bool ports_match = false;

    for (size_t i = 0; i < nb_rules_port; i++) {
        // NOTE: no break because we have to do all the list in case there
        // is a negation

        // end_port = -1 => [start_port, ...]
        if (ports[i].end_port == -1 && port >= ports[i].start_port) {
            // !negation => match
            ports_match = !ports[i].negation;
        } else if (port >= ports[i].start_port && port <= ports[i].end_port) {
            ports_match = ports[i].negation;
        }
    }

    return ports_match;
}
bool check_similarity_content(char *content, char *s) {
    size_t i = 0;
    while (content[i] != '\0') {
        if (content[i] != s[i]) {
            return false;
        }

        i++;
    }

    return true;
}
bool check_option_content(char *content, Packet *packet) {
    char *s = (char *)packet->data_link_header;

    size_t i = 0;
    while (i < packet->packet_length) {
        char c = s[i];
        if (c == content[0] && check_similarity_content(content, s + i)) {
            return true;
        }

        i++;
    }

    return false;
}
void get_rule_msg(Rule *rule, char *message) {
    RuleOption *options = rule->options;

    for (size_t i = 0; i < rule->nb_options; i++) {
        if (strcmp(options[i].keyword, "msg") == 0) {
            strcpy(message, options[i].settings[0]);
            return;
        }
    }
}


void rules_matcher(Rule *rules, int count, Packet *packet) {
    // transform the packet's data to "rule's data"
    RuleProtocol protocols[4] = {
        No_Protocol,
        No_Protocol,
        No_Protocol,
        No_Protocol,
    };
    // NOTE: if we do both ipv4, ipv6 (and even mac addresses), we could just
    // use the type 'uint128_t' instead
    uint32_t addresses[2] = {0, 0};
    uint16_t ports[2] = {0, 0};
    get_rule_protocols_from_packet(protocols, packet);
    if (packet->network_protocol == NP_Ipv4) {
        get_ipv4_from_packet(addresses, packet);
    }
    if (packet->transport_protocol != TP_None) {
        get_ports_from_packet(ports, packet);
    }

    // for every rule
    for (size_t num_rule = 0; num_rule < count; num_rule++) {
        // NOTE: the local copy here is to make the code simpler by avoiding to
        // write things such as: "rules[num_rule].x". However, this should be
        // optimized by the compiler.
        Rule *rule = rules + num_rule;
        RuleDirection direction = rule->direction;
        RuleIpv4 *sources = rule->sources;
        RuleIpv4 *destinations = rule->destinations;
        int nb_sources = rule->nb_sources;
        int nb_destinations = rule->nb_destinations;
        RulePort *source_ports = rule->source_ports;
        RulePort *destination_ports = rule->destination_ports;
        int nb_source_ports = rule->nb_source_ports;
        int nb_destination_ports = rule->nb_destination_ports;

        // 1. check if the protocols match
        if (!check_protocol_match(rule, protocols)) {
            continue;
        }

        // 2 check if the addresses match (ONLY IPV4 FOR THE MOMENT)
        // 2.1. source addresses
        if (direction == Forward &&
            !check_ipv4_match(sources, nb_sources, addresses[0])) {
            continue;
        }
        if (direction == Both_directions &&
            (!check_ipv4_match(sources, nb_sources, addresses[0]) ||
             !check_ipv4_match(sources, nb_sources, addresses[1]))) {
            continue;
        }
        // 2.2. destination addresses
        if (direction == Forward &&
            !check_ipv4_match(destinations, nb_destinations, addresses[1])) {
            continue;
        }
        if (direction == Both_directions &&
            (!check_ipv4_match(destinations, nb_destinations, addresses[0]) ||
             !check_ipv4_match(destinations, nb_destinations, addresses[1]))) {
            continue;
        }

        // 3. check if the ports match (taking the direction in account)
        // 3.1. source ports
        if (direction == Forward &&
            !check_port_match(source_ports, nb_source_ports, ports[0])) {
            continue;
        }
        if (direction == Both_directions &&
            (!check_port_match(source_ports, nb_source_ports, ports[0]) ||
             !check_port_match(source_ports, nb_source_ports, ports[1]))) {
            continue;
        }
        // 3.2. destination ports
        if (direction == Forward &&
            !check_port_match(destination_ports, nb_destination_ports,
                              ports[1])) {
            continue;
        }
        if (direction == Both_directions &&
            (!check_port_match(destination_ports, nb_destination_ports,
                               ports[0]) ||
             !check_port_match(destination_ports, nb_destination_ports,
                               ports[1]))) {
            continue;
        }

        // 4. check if the options match
        for (size_t i = 0; i < rule->nb_options; i++) {
            RuleOption *option = &(rule->options[i]);
            if (strcmp(option->keyword, "content") == 0 &&
                check_option_content(option->settings[0], packet)) {
                continue;
            }
        }

        // 5. write to syslog
        char message[150] = "packet matches rule";
        get_rule_msg(rule, message);
        write_syslog(message);
    }
}


void packet_handler(u_char *user_args, const struct pcap_pkthdr *packet_header,
                    const u_char *packet_body) {
    UserArgsPacketHandler *args = (UserArgsPacketHandler *)user_args;

    // populate the packet
    Packet packet;
    packet.packet_length = packet_header->caplen;
    populate_packet((void *)packet_body, &packet);

    // print the packet
    if (args->print_packet_headers) {
        print_packet_headers(&packet);
    }

    // check if the packet matches any rule
    rules_matcher(args->rules, args->nb_rules, &packet);

    // free the packet's application header
    if (packet.application_header != NULL) {
        free(packet.application_header);
    }
}


int main(int argc, char *argv[]) {
    int error_code = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // parse the command line arguments
    IdsArguments arguments = parse_arguments(argc, argv);
    if (arguments.print_help) {
        print_help();
        return 0;
    }

    // initialize pcap (the handle is used to identify the session)
    error_code = get_activated_handle(&handle, arguments.device, error_buffer);
    if (error_code != 0) {
        return error_code;
    }

    // open the rules' file
    FILE *file = fopen(arguments.rules_file_name, "r");
    if (file == NULL) {
        return FILE_NOT_OPENED_ERROR;
    }

    // read the rules' file
    Rule *rules = NULL;
    int nb_rules = 0;
    read_rules(file, &rules, &nb_rules);

    // handle the packets
    UserArgsPacketHandler user_args = {
        .print_packet_headers = arguments.print_packet_headers,
        .nb_rules = nb_rules,
        .rules = rules,
    };
    pcap_loop(handle, arguments.total_packet_count, packet_handler,
              (u_char *)&user_args);

    // end the program properly
    pcap_close(handle);
    free_rules(rules, nb_rules);

    return 0;
}
