#include "rules.h"

#include <stdlib.h>
#include <string.h>


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


void increase_nb_rules(Rule **rules_ptr, int *nb_rules) {
    (*nb_rules)++;
    (*rules_ptr) = realloc((*rules_ptr), (*nb_rules) * sizeof(Rule));
}
void increase_nb_ip(RuleIp **ip_ptr, int *nb_ip) {
    (*nb_ip)++;
    *(ip_ptr) = realloc((*ip_ptr), (*nb_ip) * sizeof(RuleIp));
}
void fill_in_char_buffer(char *buffer, int length_buffer, char c) {
    for (int i = 0; i < length_buffer; i++) {
        buffer[i] = c;
    }
}
// get an ip int from a string representation, e.g. "255.255.255.255/24"
// => *ip_int = 4294967295, *netmask = 24
int get_ip_and_netmask_from_str(char *ip_str, int *ip_int, char *netmask) {
    char buffer[4] = "";
    fill_in_char_buffer(buffer, 4, '\0');
    int ip_byte = 3;  // 3-0

    int index_buffer = 0;
    int i = 0;

    while (ip_str[i] != '/') {
        if (ip_str[i] == '.') {
            // get the number from the buffer
            int byte = atoi(buffer);
            // add it to ip_int
            if (ip_byte == 3) {
                (*ip_int) += byte * 256 * 256 * 256;
            }
            if (ip_byte == 2) {
                (*ip_int) += byte * 256 * 256;
            }
            if (ip_byte == 1) {
                (*ip_int) += byte * 256;
            }
            // decrement ip_byte, reinitialize the buffer/index_buffer
            ip_byte--;
            index_buffer = 0;
            fill_in_char_buffer(buffer, 4, '\0');
        } else {
            // add the digit to the buffer
            buffer[index_buffer] = ip_str[i];
            index_buffer++;
        }
    }
    // get the number from the buffer
    int byte = atoi(buffer);
    // add it to ip_int
    (*ip_int) += byte;

    // get the netmask (the netmask is the rest of *ip_str, after the '/')
    // ip_str + i     => '/<netmask>'
    // ip_str + i + 1 => '<netmask>'
    (*netmask) = atoi(ip_str + i + 1);

    return 0;
}
void get_rules_ip(RuleIp **ip_ptr, int *nb_ip, Tokens *tokens, int *i_ptr) {
    if (strcmp(tokens->tokens[*i_ptr], "!") == 0) {
        // 1. increment *i_ptr, make a copy of *nb_ip (=> start_ip)
        (*i_ptr)++;
        int start_ip = *nb_ip;
        // 2. call the function recursively
        get_rules_ip(ip_ptr, nb_ip, tokens, i_ptr);
        // 3. loop though the ip (start_ip -> *nb_ip) and inverse their negation
        for (int j = start_ip; j < *nb_ip; j++) {
            // inverse the ip's negation
            (*ip_ptr)[j].negation != (*ip_ptr)[j].negation;
        }
    } else if (strcmp(tokens->tokens[*i_ptr], "any") == 0) {
        // 1. increase *i_ptr
        (*i_ptr)++;
        // 3. add an ip to the list
        increase_nb_ip(ip_ptr, nb_ip);
        // 4. set the ip's fields
        // NOTE: we don't need to set a netmask because it's any ip
        (*ip_ptr)[(*nb_ip) - 1].negation = false;
        (*ip_ptr)[(*nb_ip) - 1].ip = -1;  // -1 => any
    } else if (strcmp(tokens->tokens[*i_ptr], "[") == 0) {
        // 2. loop until we get the closing ']'
        while (strcmp(tokens->tokens[*i_ptr], "]") != 0) {
            // 1. increase *i_ptr, to pass the '[' or the ','
            (*i_ptr)++;
            // 2. call the function recursively to get the ip
            get_rules_ip(ip_ptr, nb_ip, tokens, i_ptr);
        }
    } else {
        // 1. increment *i_ptr
        (*i_ptr)++;
        // 2. add an ip to the list
        increase_nb_ip(ip_ptr, nb_ip);
        // 3. get the ip and the netmask
        RuleIp *new_ip = &(*ip_ptr)[(*nb_ip) - 1];
        new_ip->negation = false;
        get_ip_and_netmask_from_str(tokens->tokens[*i_ptr], &new_ip->ip,
                                    &new_ip->netmask);
    }
}

int get_rule_action(Rule *rule, Tokens *tokens, int *i_ptr) {
    if (strcmp(tokens->tokens[*i_ptr], "alert") == 0) {
        rule->action = Alert;
    } else if (strcmp(tokens->tokens[*i_ptr], "pass") == 0) {
        rule->action = Pass;
    } else if (strcmp(tokens->tokens[*i_ptr], "drop") == 0) {
        rule->action = Drop;
    } else if (strcmp(tokens->tokens[*i_ptr], "reject") == 0) {
        rule->action = Reject;
    } else if (strcmp(tokens->tokens[*i_ptr], "rejectsrc") == 0) {
        rule->action = Rejectsrc;
    } else if (strcmp(tokens->tokens[*i_ptr], "rejectdst") == 0) {
        rule->action = Rejectdst;
    } else if (strcmp(tokens->tokens[*i_ptr], "rejectboth") == 0) {
        rule->action = Rejectboth;
    }
    // else {
    //     return ERROR_ACTION_EXPECTED;
    // }

    (*i_ptr)++;
    return 0;
}
int get_rule_protocol(Rule *rule, Tokens *tokens, int *i_ptr) {
    if (strcmp(tokens->tokens[*i_ptr], "tcp") == 0) {
        rule->protocol = Tcp;
    } else if (strcmp(tokens->tokens[*i_ptr], "udp") == 0) {
        rule->protocol = Udp;
    } else if (strcmp(tokens->tokens[*i_ptr], "icmp") == 0) {
        rule->protocol = Icmp;
    } else if (strcmp(tokens->tokens[*i_ptr], "ip") == 0) {
        rule->protocol = Ip;
    } else if (strcmp(tokens->tokens[*i_ptr], "http") == 0) {
        rule->protocol = Http;
    } else if (strcmp(tokens->tokens[*i_ptr], "tls") == 0) {
        rule->protocol = Tls;
    } else if (strcmp(tokens->tokens[*i_ptr], "ssh") == 0) {
        rule->protocol = Ssh;
    } else if (strcmp(tokens->tokens[*i_ptr], "ftp") == 0) {
        rule->protocol = Ftp;
    } else if (strcmp(tokens->tokens[*i_ptr], "tftp") == 0) {
        rule->protocol = Tftp;
    } else if (strcmp(tokens->tokens[*i_ptr], "smtp") == 0) {
        rule->protocol = Smtp;
    } else if (strcmp(tokens->tokens[*i_ptr], "imap") == 0) {
        rule->protocol = Imap;
    } else if (strcmp(tokens->tokens[*i_ptr], "ntp") == 0) {
        rule->protocol = Ntp;
    } else if (strcmp(tokens->tokens[*i_ptr], "dhcp") == 0) {
        rule->protocol = Dhcp;
    } else if (strcmp(tokens->tokens[*i_ptr], "dns") == 0) {
        rule->protocol = Dns;
    }
    // else {
    //     return ERROR_PROTOCOL_EXPECTED;
    // }

    (*i_ptr)++;
    return 0;
}
int get_rule_source_ip(Rule *rule, Tokens *tokens, int *i_ptr) {
    // it needs to be initialized here because the next function calls itself
    // recursively and therefore can't initialize these fields
    rule->sources = NULL;
    rule->nb_sources = 0;
    get_rules_ip(&rule->sources, &rule->nb_sources, tokens, i_ptr);
}
int get_rule_source_port(Rule *rule, Tokens *tokens, int *i_ptr) {
    // 1. check '!'
    // 2. check 'any'
    // 3. check '['
}
int get_rule_direction(Rule *rule, Tokens *tokens, int *i_ptr) {
    if (strcmp(tokens->tokens[*i_ptr], "->") == 0) {
        rule->direction = Forward;
    } else if (strcmp(tokens->tokens[*i_ptr], "<>") == 0) {
        rule->direction = Both_directions;
    }
    // else {
    //     return ERROR_DIRECTION_EXPECTED;
    // }

    (*i_ptr)++;
    return 0;
}
int get_rule_destination_ip(Rule *rule, Tokens *tokens, int *i_ptr) {
    // it needs to be initialized here because the next function calls itself
    // recursively and therefore can't initialize these fields
    rule->destinations = NULL;
    rule->nb_destinations = 0;
    get_rules_ip(&rule->destinations, &rule->nb_destinations, tokens, i_ptr);
}
int get_rule_destination_port(Rule *rule, Tokens *tokens, int *i_ptr) {}
int get_rule_options(Rule *rule, Tokens *tokens, int *i_ptr) {}

void extract_rules(Rule *rules, int *nb_rules, Tokens *tokens) {
    int i = 0;
    while (i < tokens->nb_tokens) {
        // add an empty rule to the list
        increase_nb_rules(&rules, nb_rules);
        Rule *rule = &rules[(*nb_rules) - 1];

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
