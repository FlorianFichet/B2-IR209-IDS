#include <stdbool.h>
#include <stdlib.h>

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
void get_rule_ipv4_from_packet(RuleIpv4 *ips, Packet *packet) {
    //
}


void rules_matcher(Rule *rules, int count, Packet *packet) {
    // transform the packet's data to "rule's data"
    RuleProtocol protocols[4];
    RuleIpv4 ips[2];
    get_rule_protocols_from_packet(protocols, packet);
    if (packet->network_protocol == NP_Ipv4) {
        get_rule_ipv4_from_packet(ips, packet);
    }

    // for every rule
    for (size_t num_rule = 0; num_rule < count; num_rule++) {
        Rule *rule = rules + num_rule;

        // 1. check if the protocols match
        bool protocols_match = false;
        for (size_t i = 0; i < 4; i++) {
            if (rule->protocol == protocols[i]) {
                protocols_match = true;
                break;
            }
        }
        if (!protocols_match) {
            continue;
        }

        // 2. check if the ip match (taking the direction in account)
        // 3. check if the ports match (taking the direction in account)
        // 4. check if the options match
        // 5. write to syslog
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
