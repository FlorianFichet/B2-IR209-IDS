#include <stdbool.h>
#include <stdio.h>

#define LENGTH_RULE_MESSAGE 150


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
    // NOTE: "RP" stands for "Rule Protocol"
    RP_Ethernet,
    RP_Ipv4,
    RP_Ipv6,
    RP_Tcp,
    RP_Udp,
    RP_Icmp,
    RP_Http,
    RP_Tls,  // (this includes ssl)
    RP_Ssh,
    RP_Ftp,
    RP_Tftp,
    RP_Smtp,
    RP_Imap,
    RP_Ntp,
    RP_Dhcp,
    RP_Dns,
    RP_No_Protocol,
} typedef RuleProtocol;
struct rule_ipv4 {
    bool negation;
    int ip;        // -1 => any
    char netmask;  // CIDR notation (ip/xx)
} typedef RuleIpv4;
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

    RuleIpv4 *sources;  // there could be multiple sources
    int nb_sources;
    RuleIpv4 *destinations;
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
void free_rules(Rule *rules, int nb_rules);
