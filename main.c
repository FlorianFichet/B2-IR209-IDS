#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

#include "populate.h"
#include "rules.h"


#define SNIFFER_ERROR_HANDLE_NOT_CREATED 1
#define SNIFFER_ERROR_HANDLE_NOT_ACTIVATED 2
#define FILE_NOT_OPENED_ERROR 3


#define TIME_BUFFER_LENGTH 30


struct ids_arguments {
    bool print_help;
    bool print_packet_headers;
    bool print_all;
    bool print_logs;
    char *device;
    char *rules_file_name;
    int total_packet_count;
} typedef IdsArguments;


struct user_args_packet_handler {
    int nb_rules;
    Rule *rules;
    IdsArguments ids_arguments;
} typedef UserArgsPacketHandler;


void write_syslog(char *message, Packet *packet) {
    // NOTE: options are coded on an int
    // LOG_CONS   = 0x02 = log on the console if errors in sending
    // LOG_PID    = 0x01 = log the pid with each message
    // LOG_NDELAY = 0x08 = don't delay open
    openlog("Ids", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    // LOG_ALERT = action must be taken immediately
    syslog(LOG_ALERT, message);

    closelog();
}


IdsArguments parse_arguments(int argc, char *argv[]) {
    IdsArguments arguments = {
        .print_help = false,
        .print_packet_headers = false,
        .print_all = false,
        .print_logs = false,
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
        } else if (strcmp(s, "--print-all") == 0) {
            arguments.print_all = true;
        } else if (strcmp(s, "--print-logs") == 0) {
            arguments.print_logs = true;
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
void print_logs(char *message, Packet *packet) {
    // get the time
    time_t global_time = packet->packet_header->ts.tv_sec;
    struct tm *local_time = localtime(&global_time);
    int milliseconds = packet->packet_header->ts.tv_usec / 1000;
    int microseconds = packet->packet_header->ts.tv_usec % 1000;

    char date_stamp[TIME_BUFFER_LENGTH];
    char time_stamp[TIME_BUFFER_LENGTH];
    char date_time[4 * TIME_BUFFER_LENGTH];

    // put the time to string format
    strftime(date_stamp, TIME_BUFFER_LENGTH, "%F (%a)", local_time);
    strftime(time_stamp, TIME_BUFFER_LENGTH, "%H:%M:%S", local_time);

    sprintf(date_time, "%s %s %d ms %d µs", date_stamp, time_stamp,
            milliseconds, microseconds);
    printf("log : %s : %s\n", date_time, message);
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
        case PP_Ethernet:
            protocols[0] = RP_Ethernet;
            break;
        default:
            protocols[0] = RP_No_Protocol;
            break;
    }
    switch (packet->network_protocol) {
        case PP_Ipv4:
            protocols[1] = RP_Ipv4;
            break;
        case PP_Ipv6:
            protocols[1] = RP_Ipv6;
            break;
        default:
            protocols[1] = RP_No_Protocol;
            break;
    }
    switch (packet->transport_protocol) {
        case PP_Tcp:
            protocols[2] = RP_Tcp;
            break;
        case PP_Udp:
            protocols[2] = RP_Udp;
            break;
        default:
            protocols[2] = RP_No_Protocol;
            break;
    }
    switch (packet->application_protocol) {
        case PP_Http:
            protocols[3] = RP_Http;
            break;
        default:
            protocols[3] = RP_No_Protocol;
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
        case PP_Tcp:;
            TcpSegment *tcp_header = (TcpSegment *)packet->transport_header;
            ports[0] = tcp_header->th_source_port;
            ports[1] = tcp_header->th_destination_port;
            break;
        case PP_Udp:;
            UdpSegment *udp_header = (UdpSegment *)packet->transport_header;
            ports[0] = udp_header->port_source;
            ports[1] = udp_header->port_destination;
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
bool check_addresses_match_with_direction(Rule *rule, uint32_t addresses[2]) {
    // NOTE: the local copy here is to make the code simpler by avoiding to
    // write: "rule->x". However, this should be optimized by the compiler.
    RuleDirection direction = rule->direction;
    RuleIpv4 *sources = rule->sources;
    RuleIpv4 *destinations = rule->destinations;
    int nb_sources = rule->nb_sources;
    int nb_destinations = rule->nb_destinations;

    // 1. direction forward (->)
    if (direction == Forward &&
        (!check_ipv4_match(sources, nb_sources, addresses[0]) ||
         !check_ipv4_match(destinations, nb_destinations, addresses[1]))) {
        return false;
    }

    // 2. both directions (<>)
    if (direction == Both_directions &&
        (!check_ipv4_match(sources, nb_sources, addresses[0]) ||
         !check_ipv4_match(sources, nb_sources, addresses[1])) &&
        (!check_ipv4_match(destinations, nb_destinations, addresses[0]) ||
         !check_ipv4_match(destinations, nb_destinations, addresses[1]))) {
        return false;
    }

    return true;
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
bool check_ports_match_with_direction(Rule *rule, uint16_t ports[2]) {
    // NOTE: the local copy here is to make the code simpler by avoiding to
    // write: "rule->x". However, this should be optimized by the compiler.
    RuleDirection direction = rule->direction;
    RulePort *source_ports = rule->source_ports;
    RulePort *destination_ports = rule->destination_ports;
    int nb_source_ports = rule->nb_source_ports;
    int nb_destination_ports = rule->nb_destination_ports;

    // 1. direction forward (->)
    if (direction == Forward &&
        (!check_port_match(source_ports, nb_source_ports, ports[0]) ||
         !check_port_match(destination_ports, nb_destination_ports,
                           ports[1]))) {
        return false;
    }

    // 2. both directions (<>)
    if (direction == Both_directions &&
        (!check_port_match(source_ports, nb_source_ports, ports[0]) ||
         !check_port_match(source_ports, nb_source_ports, ports[1])) &&
        (!check_port_match(destination_ports, nb_destination_ports, ports[0]) ||
         !check_port_match(destination_ports, nb_destination_ports,
                           ports[1]))) {
        return false;
    }

    return true;
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
    uint32_t packet_length = packet->packet_header->caplen;

    size_t i = 0;
    while (i < packet_length) {
        char c = s[i];
        if (c == content[0] && check_similarity_content(content, s + i)) {
            return true;
        }

        i++;
    }

    return false;
}
bool check_options_match(Rule *rule, Packet *packet) {
    for (size_t i = 0; i < rule->nb_options; i++) {
        RuleOption *option = &(rule->options[i]);
        // if the "content" is found in the packet, the option match
        if (strcmp(option->keyword, "content") == 0 &&
            !check_option_content(option->settings[0], packet)) {
            return false;
        }
    }

    return true;
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


void rules_matcher(Rule *rules, int count, Packet *packet,
                   UserArgsPacketHandler *args) {
    // transform the packet's data to "rule's data"
    RuleProtocol protocols[4] = {
        RP_No_Protocol,
        RP_No_Protocol,
        RP_No_Protocol,
        RP_No_Protocol,
    };
    // NOTE: if we do both ipv4, ipv6 (and even mac addresses), we could just
    // use the type 'uint128_t' instead
    uint32_t addresses[2] = {0, 0};
    uint16_t ports[2] = {0, 0};
    get_rule_protocols_from_packet(protocols, packet);
    if (packet->network_protocol == PP_Ipv4) {
        get_ipv4_from_packet(addresses, packet);
    }
    if (packet->transport_protocol != PP_None) {
        get_ports_from_packet(ports, packet);
    }

    // for every rule
    for (size_t num_rule = 0; num_rule < count; num_rule++) {
        Rule *rule = rules + num_rule;

        // 1. check if the packet matches the rule
        if (!check_protocol_match(rule, protocols) ||
            !check_addresses_match_with_direction(rule, addresses) ||
            !check_ports_match_with_direction(rule, ports) ||
            !check_options_match(rule, packet)) {
            continue;
        }

        // 2. write to syslog
        char message[LENGTH_RULE_MESSAGE] = "packet matches rule";
        get_rule_msg(rule, message);
        write_syslog(message, packet);

        // 3. if the user wants to print the log, print it
        if (args->ids_arguments.print_logs) {
            print_logs(message, packet);
        }
    }
}


void packet_handler(u_char *user_args, const struct pcap_pkthdr *packet_header,
                    const u_char *packet_body) {
    UserArgsPacketHandler *args = (UserArgsPacketHandler *)user_args;

    // populate the packet
    Packet packet = {
        .data_link_protocol = PP_Ethernet,
        .network_protocol = PP_None,
        .transport_protocol = PP_None,
        .application_protocol = PP_None,

        .data_link_header = (void *)packet_body,
        .network_header = NULL,
        .transport_header = NULL,
        .application_header = NULL,
    };
    packet.packet_header = (struct pcap_pkthdr *)packet_header;
    populate_packet((void *)packet_body, &packet);

    // print the packet headers/data
    if (args->ids_arguments.print_packet_headers ||
        args->ids_arguments.print_all) {
        print_packet_headers(&packet);
    }
    if (args->ids_arguments.print_all) {
        print_packet_data(&packet);
    }


    // check if the packet matches any rule
    rules_matcher(args->rules, args->nb_rules, &packet, args);

    // free the packet's application header
    if (packet.application_header != NULL &&
        packet.application_protocol != PP_None) {
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
        .nb_rules = nb_rules,
        .rules = rules,
        .ids_arguments = arguments,
    };
    pcap_loop(handle, arguments.total_packet_count, packet_handler,
              (u_char *)&user_args);

    // end the program properly
    pcap_close(handle);
    free_rules(rules, nb_rules);

    return 0;
}
