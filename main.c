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


void rules_matcher(Rule *rules_ds, int count, Packet *packet) {
    //
}


void packet_handler(u_char *user_args, const struct pcap_pkthdr *packet_header,
                    const u_char *packet_body) {
    UserArgsPacketHandler *args = (UserArgsPacketHandler *)user_args;

    // populate the packet
    Packet packet;
    populate_packet((void *)packet_body, &packet);

    // print the packet
    if (args->print_packet_headers) {
        print_packet_headers(&packet);
    }

    // check if the packet matches any rule
    rules_matcher(args->rules, args->nb_rules, &packet);
}


int main(int argc, char *argv[]) {
    int error_code = 0;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. parse the command line arguments
    IdsArguments arguments = parse_arguments(argc, argv);
    if (arguments.print_help) {
        print_help();
        return 0;
    }


    // 2. initialize pcap (the handle is used to identify the session)
    error_code = get_activated_handle(&handle, arguments.device, error_buffer);
    if (error_code != 0) {
        return error_code;
    }

    // 3. open the rules' file
    FILE *file = fopen(arguments.rules_file_name, "r");
    if (file == NULL) {
        return FILE_NOT_OPENED_ERROR;
    }

    // 4. read the rules' file
    Rule *rules = NULL;
    int nb_rules = 0;
    read_rules(file, &rules, &nb_rules);

    // 5. handle the packets
    pcap_loop(handle, arguments.total_packet_count, packet_handler, NULL);

    // 6. close pcap
    pcap_close(handle);

    // 7. free the rules
    free_rules(rules, nb_rules);

    return 0;
}
