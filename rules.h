#include <stdbool.h>
#include <stdio.h>

enum rule_action {
    Alert,
    Pass,
    Drop,
    Reject,
    Rejectsrc,
    Rejectdst,
    Rejectboth,
} typedef RuleAction;
enum rule_protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,
    Http,
    Tls,  // (this includes ssl)
    Ssh,
    Ftp,
    Tftp,
    Smtp,
    Imap,
    Ntp,
    Dhcp,
    Dns,
} typedef RuleProtocol;
struct rule_ip {
    bool negation;
    int ip;        // -1 => any
    char netmask;  // CIDR notation (ip/xx)
} typedef RuleIp;
struct rule_port {
    bool negation;
    // 0 to -1 => any
    // range: [start_port, end_port]
    int start_port;
    int end_port;
} typedef RulePort;
enum rule_direction {
    Forward,          // ->
    Both_directions,  // <>
} typedef RuleDirection;
struct rule_option {
    char *keyword;
    char **settings;
    int nb_settings;
} typedef RuleOption;


struct ids_rule {
    RuleAction action;
    RuleProtocol protocol;

    RuleIp *sources;  // there could be multiple sources
    int nb_sources;
    RuleIp *destinations;
    int nb_destinations;

    RulePort *source_ports;  // there could be multiple ports
    int nb_source_ports;
    RulePort *destination_ports;
    int nb_destination_ports;

    RuleDirection direction;
    RuleOption *options;  // there could be multiple options
    int nb_options;
} typedef Rule;


void read_rules(FILE *file, Rule **rules_ds, int *count);
