#include "rules.h"

#include <stdlib.h>


// struct that can contain every token
struct rules_tokens {
    char **tokens;
    int nb_tokens;
} typedef Tokens;

// function that adds a token to the 'Tokens' struct
void add_token(char *token, int token_size, Tokens *tokens) {
    // resize : (char**) tokens->tokens
    tokens->nb_tokens++;
    tokens->tokens =
        realloc(tokens->tokens, tokens->nb_tokens * sizeof(char *));

    // allocate enough memory to store the token
    tokens->tokens[tokens->nb_tokens - 1] = malloc(token_size * sizeof(char));

    // copy the token into the allocated space
    char *s = tokens->tokens[tokens->nb_tokens - 1];
    s[--token_size] = '\0';  // --token_size => because we start counting at 0
    --token_size;
    while (token_size >= 0) {
        s[token_size] = token[token_size];
        --token_size;
    }
}

// this function tokenizes the file that contains the rules, i.e. it separates
// every word, parentheses, etc. into separate strings for later analysis
void tokenize_rules(FILE *file, Tokens *tokens) {
    char c = ' ';
    char buffer[1000];
    int buffer_index = 0;
    bool token_is_over = false;

    while (c != EOF) {
        c = fgetc(file);

        switch (c) {
            case EOF:
                break;

            // add the buffer if not empty
            case ' ':
            case '\t':
            case '\n':
                if (buffer_index > 0) {
                    // the buffer contains the token
                    // buffer_index needs to be incremented to account for the
                    // '\0'
                    add_token(buffer, buffer_index + 1, tokens);
                    buffer_index = 0;
                }
                break;

            // add the buffer if not empty, then add the character
            case '(':
            case ')':
            case ',':
            case ';':
            case ':':
            case '"':
            case '[':
            case ']':
            case '!':
                if (buffer_index > 0) {
                    // the buffer contains the token
                    // buffer_index needs to be incremented to account for the
                    // '\0'
                    add_token(buffer, buffer_index + 1, tokens);
                    // add the character 'c', 2 => accounts for the '\0'
                    add_token(&c, 2, tokens);
                    buffer_index = 0;
                }
                break;

            default:
                buffer[buffer_index] = c;
                buffer_index++;
                break;
        }
    }
}


void increase_size_rules(Rule *rules, int *nb_rules) {
    *nb_rules++;
    rules = realloc(rules, *nb_rules * sizeof(Rule));
}
int get_rule_action(Rule *rule, Tokens *tokens, int *i) {
    if (strcmp(tokens->tokens[i], "alert")) {
        rule->action = Alert;
    } else if (strcmp(tokens->tokens[i], "pass")) {
        rule->action = Pass;
    } else if (strcmp(tokens->tokens[i], "drop")) {
        rule->action = Drop;
    } else if (strcmp(tokens->tokens[i], "reject")) {
        rule->action = Reject;
    } else if (strcmp(tokens->tokens[i], "rejectsrc")) {
        rule->action = Rejectsrc;
    } else if (strcmp(tokens->tokens[i], "rejectdst")) {
        rule->action = Rejectdst;
    } else if (strcmp(tokens->tokens[i], "rejectboth")) {
        rule->action = Rejectboth;
    }
    // else {
    //     return ERROR_ACTION_EXPECTED;
    // }

    *i++;
    return 0;
}
void get_rule_protocol(Rule *rule, Tokens *tokens, int *i) {
    if (strcmp(tokens->tokens[i], "tcp")) {
        rule->protocol = Tcp;
    } else if (strcmp(tokens->tokens[i], "udp")) {
        rule->protocol = Udp;
    } else if (strcmp(tokens->tokens[i], "icmp")) {
        rule->protocol = Icmp;
    } else if (strcmp(tokens->tokens[i], "ip")) {
        rule->protocol = Ip;
    } else if (strcmp(tokens->tokens[i], "http")) {
        rule->protocol = Http;
    } else if (strcmp(tokens->tokens[i], "tls")) {
        rule->protocol = Tls;
    } else if (strcmp(tokens->tokens[i], "ssh")) {
        rule->protocol = Ssh;
    } else if (strcmp(tokens->tokens[i], "ftp")) {
        rule->protocol = Ftp;
    } else if (strcmp(tokens->tokens[i], "tftp")) {
        rule->protocol = Tftp;
    } else if (strcmp(tokens->tokens[i], "smtp")) {
        rule->protocol = Smtp;
    } else if (strcmp(tokens->tokens[i], "imap")) {
        rule->protocol = Imap;
    } else if (strcmp(tokens->tokens[i], "ntp")) {
        rule->protocol = Ntp;
    } else if (strcmp(tokens->tokens[i], "dhcp")) {
        rule->protocol = Dhcp;
    } else if (strcmp(tokens->tokens[i], "dns")) {
        rule->protocol = Dns;
    }
    // else {
    //     return ERROR_PROTOCOL_EXPECTED;
    // }

    *i++;
    return 0;
}
void get_rule_source_ip(Rule *rule, Tokens *tokens, int *i) {}
void get_rule_source_port(Rule *rule, Tokens *tokens, int *i) {}
void get_rule_direction(Rule *rule, Tokens *tokens, int *i) {}
void get_rule_destination_ip(Rule *rule, Tokens *tokens, int *i) {}
void get_rule_destination_port(Rule *rule, Tokens *tokens, int *i) {}
void get_rule_options(Rule *rule, Tokens *tokens, int *i) {}

void extract_rules(Rule *rules, int *nb_rules, Tokens *tokens) {
    int i = 0;
    while (i < tokens->nb_tokens) {
        // add an empty rule to the list
        increase_size_rules(rules, nb_rules);
        Rule *rule = &rules[*nb_rules - 1];

        get_rule_action(rule, tokens, &i);
        get_rule_protocol(rule, tokens, &i);
        get_rule_source_ip(rule, tokens, &i);
        get_rule_source_port(rule, tokens, &i);
        get_rule_direction(rule, tokens, &i);
        get_rule_destination_ip(rule, tokens, &i);
        get_rule_destination_port(rule, tokens, &i);
        get_rule_options(rule, tokens, &i);

        // NOTE: no need to increase i (i++) as it is incremented in the
        // functions used above
    }
}


void read_rules(FILE *file, Rule *rules_ds, int *count) {
    // 1. tokenize the text
    Tokens tokens = {NULL, 0};
    tokenize_rules(file, &tokens);

    // 2. close the file handle
    // int error_code = fclose(file);
    // if (error_code != 0) {
    //     return FILE_NOT_CLOSED_ERROR;
    // }
    fclose(file);

    // 3. extract the rules
    extract_rules(rules_ds, count, &tokens);
}
