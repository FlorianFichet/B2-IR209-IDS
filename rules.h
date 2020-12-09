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
    tls, // (this includes ssl)
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


struct ids_rule {
    RuleAction action;
    RuleProtocol protocol;
} typedef Rule;


void read_rules(FILE *file, Rule *rules_ds, int count);
