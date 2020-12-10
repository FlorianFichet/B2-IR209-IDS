#include <stdbool.h>
#include <stdio.h>

enum rule_action {
    alert,
    pass,
    drop,
    reject,
    rejectsrc,
    rejectdst,
    rejectboth,
} typedef RuleAction;
enum rule_protocol {
    tcp,
    udp,
    icmp,
    ip,
    http,
    ftp,
    tls,  // (this includes ssl)
    smb,
    dns,
    dcerpc,
    ssh,
    smtp,
    imap,
    modbus,
    dnp3,
    enip,
    nfs,
    ikev2,
    krb5,
    ntp,
    dhcp,
    rfb,
    rdp,
    snmp,
    tftp,
    sip,
    http2,
} typedef RuleProtocol;
struct rule_ip {
    bool negation;
    int ip;        // -1 => any
    char netmask;  // CIDR notation (ip/xx)
} typedef RuleIp;
struct rule_port {
    bool negation;
    int port;  // -1 => any
} typedef RulePort;
enum rule_direction {
    forward,          // ->
    both_directions,  // <>
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


void read_rules(FILE *file, Rule *rules_ds, int *count);
