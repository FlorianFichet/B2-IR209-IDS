#include "populate.h"
#include "rules.h"


#define SNIFFER_ERROR_HANDLE_NOT_CREATED 1
#define SNIFFER_ERROR_HANDLE_NOT_ACTIVATED 2
#define FILE_NOT_OPENED_ERROR 3


void rule_matcher(Rule *rules_ds, ETHER_Frame *frame) {}
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header,
                       const u_char *packet) {}
int get_activated_handle(pcap_t **handle_ptr, char device[],
                         char error_buffer[]);


int main(int argc, char *argv[]) {
    int error_code = 0;
    int total_packet_count = 10;
    char *device = "eth0";
    char *rules_file_name = "/home/user/Documents/projet/ids.rules";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. parse the command line arguments

    // 2. initialize pcap (the handle is used to identify the session)
    error_code = get_activated_handle(&handle, device, error_buffer);
    if (error_code != 0) {
        return error_code;
    }

    // 3. read the rules' file
    FILE *file = fopen(rules_file_name, "r");
    if (file == NULL) {
        return FILE_NOT_OPENED_ERROR;
    }

    Rule *rules;
    int nb_rules = 0;
    read_rules(file, rules, &nb_rules);

    pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

    return 0;
}


// get the activated handle into 'handle', it is opened on 'device',
// returns 0 on success
int get_activated_handle(pcap_t **handle_ptr, char device[],
                         char error_buffer[]) {
    *handle_ptr = pcap_create(device, error_buffer);
    if (*handle_ptr == NULL) {
        pcap_close(*handle_ptr);
        return SNIFFER_ERROR_HANDLE_NOT_CREATED;
    }
    if (pcap_activate(*handle_ptr) != 0) {
        return SNIFFER_ERROR_HANDLE_NOT_ACTIVATED;
    }
    return 0;
}
