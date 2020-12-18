#include <stdlib.h>

#include "populate.h"
#include "rules.h"


#define SNIFFER_ERROR_HANDLE_NOT_CREATED 1
#define SNIFFER_ERROR_HANDLE_NOT_ACTIVATED 2
#define FILE_NOT_OPENED_ERROR 3


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

    // 2. activate the handle
    if (pcap_activate(*handle_ptr) != 0) {
        return SNIFFER_ERROR_HANDLE_NOT_ACTIVATED;
    }

    return 0;
}


void rule_matcher(Rule *rules_ds, ETHER_Frame *frame) {}
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header,
                       const u_char *packet) {}


int main(int argc, char *argv[]) {
    int error_code = 0;
    int total_packet_count = 0;
    char *device = "eth0";
    char *rules_file_name = "/home/user/Downloads/projet/ids.rules";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. parse the command line arguments

    // 2. initialize pcap (the handle is used to identify the session)
    error_code = get_activated_handle(&handle, device, error_buffer);
    if (error_code != 0) { return error_code; }

    // 3. open the rules' file
    FILE *file = fopen(rules_file_name, "r");
    if (file == NULL) { return FILE_NOT_OPENED_ERROR; }

    // 4. read the rules' file
    Rule *rules = NULL;
    int nb_rules = 0;
    read_rules(file, rules, &nb_rules);

    // 5. handle the packets
    pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

    // 6. close pcap
    pcap_close(handle);

    // 7. free the rules
    for (int i = 0; i < nb_rules; i++) {
        Rule *rule = &rules[i];

        // 6.1. free ip/ports sources/destinations
        free(rule->sources);
        free(rule->destinations);
        free(rule->source_ports);
        free(rule->destination_ports);

        // 6.2. free options
        free(rule->options->keyword);
        for (int j = 0; j < rule->options->nb_settings; j++) {
            free(rule->options->settings[j]);
        }

        // 6.3. free the rule
        free(rule);
    }

    return 0;
}
