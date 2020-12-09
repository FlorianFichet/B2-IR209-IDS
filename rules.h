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


struct ids_rule {
    RuleAction action;
} typedef Rule;


void read_rules(FILE *file, Rule *rules_ds, int count);
