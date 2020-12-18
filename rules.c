#include "rules.h"

#include <stdlib.h>
#include <string.h>


// struct that can contain every token
struct rules_tokens {
    char **tokens;
    int nb_tokens;
} typedef Tokens;


void get_rules_ip(RuleIp **ip_ptr, int *nb_ip, Tokens *tokens, int *i_ptr);
void get_rules_port(RulePort **port_ptr, int *nb_ports, Tokens *tokens,
                    int *i_ptr);


void increase_nb_tokens(Tokens *tokens) {
    // resize : (char**) tokens->tokens
    tokens->nb_tokens++;
    tokens->tokens =
        realloc(tokens->tokens, tokens->nb_tokens * sizeof(char *));
}
void increase_nb_rules(Rule **rules_ptr, int *nb_rules) {
    (*nb_rules)++;
    (*rules_ptr) = realloc((*rules_ptr), (*nb_rules) * sizeof(Rule));
}
void increase_nb_ip(RuleIp **ip_ptr, int *nb_ip) {
    (*nb_ip)++;
    (*ip_ptr) = realloc((*ip_ptr), (*nb_ip) * sizeof(RuleIp));
}
void increase_nb_ports(RulePort **port_ptr, int *nb_ports) {
    (*nb_ports)++;
    (*port_ptr) = realloc((*port_ptr), (*nb_ports) * sizeof(RulePort));
}
void increase_nb_options(RuleOption **options_ptr, int *nb_options) {
    (*nb_options)++;
    (*options_ptr) =
        realloc((*options_ptr), (*nb_options) * sizeof(RuleOption));
}
void increase_nb_option_settings(char ***settings_ptr, int *nb_settings) {
    (*nb_settings)++;
    (*settings_ptr) = realloc((*settings_ptr), (*nb_settings) * sizeof(char **));
}


// we need a custom made function because the token we want copy doesn't end
// with '\0'
void copy_token(char *token, int token_size, Tokens *tokens) {
    // copy the token into the allocated space
    char *s = tokens->tokens[tokens->nb_tokens - 1];
    s[--token_size] = '\0';  // --token_size => because we start counting at 0
    --token_size;
    while (token_size >= 0) {
        s[token_size] = token[token_size];
        --token_size;
    }
}


// function that adds a token to the 'Tokens' struct
void add_token(char *token, int token_size, Tokens *tokens) {
    increase_nb_tokens(tokens);

    // allocate enough memory to store the token
    tokens->tokens[tokens->nb_tokens - 1] = malloc(token_size * sizeof(char));

    copy_token(token, token_size, tokens);
}

// this function tokenizes the file that contains the rules, i.e. it separates
// every word, parentheses, etc. into separate strings for later analysis
void tokenize_rules(FILE *file, Tokens *tokens) {
    char c = ' ';
    char buffer[1000];
    int buffer_index = 0;

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
            case '[':
            case ']':
            case '!':
                if (buffer_index > 0) {
                    // the buffer contains the token
                    // buffer_index needs to be incremented to account for the
                    // '\0'
                    add_token(buffer, buffer_index + 1, tokens);
                }
                // add the character 'c', 2 => accounts for the '\0'
                add_token(&c, 2, tokens);
                buffer_index = 0;
                break;

            case '"':
                // add the buffer (if not empty)
                if (buffer_index > 0) {
                    // the buffer contains the token
                    // buffer_index needs to be incremented to account for
                    // the '\0'
                    add_token(buffer, buffer_index + 1, tokens);
                }
                // add the quote '"' to the buffer
                buffer[0] = c;
                buffer_index = 1;

                // add every character to the buffer until there is a second
                // quote
                c = fgetc(file);
                while (c != '"') {
                    buffer[buffer_index] = c;
                    buffer_index++;
                    c = fgetc(file);
                }
                // add the second quote to the buffer
                buffer[buffer_index] = c;
                buffer_index++;
                // finally add the buffer
                add_token(buffer, buffer_index + 1, tokens);
                buffer_index = 0;

                break;

            default:
                buffer[buffer_index] = c;
                buffer_index++;
                break;
        }
    }
}


void fill_in_char_buffer(char *buffer, int length_buffer, char c) {
    for (int i = 0; i < length_buffer; i++) {
        buffer[i] = c;
    }
}
void copy_string_in_heap(char *string, char **copy) {
    // +1 for the '\0'
    int length = strlen(string) + 1;
    (*copy) = malloc(length * sizeof(char));
    strcpy((*copy), string);
}

// get an ip int from a string representation, e.g. "255.255.255.255/24"
// => *ip_int = 4294967295, *netmask = 24
int get_ip_and_netmask_from_str(char *ip_str, int *ip_int, char *netmask) {
    char buffer[4] = "";
    fill_in_char_buffer(buffer, 4, '\0');
    int ip_byte = 3;  // 3-0

    int index_buffer = 0;
    int i = 0;

    while (ip_str[i] != '/' && ip_str[i] != '\0') {
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

    if (ip_str[i] == '/') {
        // get the netmask (the netmask is the rest of *ip_str, after the '/')
        // ip_str + i     => '/<netmask>'
        // ip_str + i + 1 => '<netmask>'
        (*netmask) = atoi(ip_str + i + 1);
    } else {
        // if there's only an ip (a host, not a network), it's as if the netmask
        // had a value of 32 (CIDR notation)
        (*netmask) = 32;
    }


    return 0;
}
void get_port_from_str(RulePort *port, Tokens *tokens, int *i_ptr) {
    // 1. get start_port
    port->start_port = atoi(tokens->tokens[*i_ptr]);
    // 2. check if the next token is ':'
    (*i_ptr)++;
    char *token = tokens->tokens[*i_ptr];
    if (strcmp(token, ":") == 0) {
        // 3. if it is, get end_port
        (*i_ptr)++;  // pass the token ':'
        port->end_port = atoi(tokens->tokens[*i_ptr]);
        (*i_ptr)++;
    } else {
        // 4. otherwise, end_port = start_port
        port->end_port = port->start_port;
    }
}


void get_option_settings(RuleOption *option, Tokens *tokens, int *i_ptr) {
    // example of syntax: option = ... :setting,setting;

    char *token = tokens->tokens[*i_ptr];

    // get option settings
    while (strcmp(token, ";") != 0) {
        // increase *i_ptr to account for the ':' or the ','
        if (strcmp(token, ":") == 0 || strcmp(token, ",") == 0) {
            (*i_ptr)++;
            token = tokens->tokens[*i_ptr];
        }

        // add new setting & copy it
        increase_nb_option_settings(&option->settings, &option->nb_settings);
        copy_string_in_heap(token, &option->settings[option->nb_settings - 1]);

        (*i_ptr)++;
        token = tokens->tokens[*i_ptr];
    }

    // increase *i_ptr to account for the ';'
    (*i_ptr)++;
}

void inverse_negation_ip(RuleIp **ip_ptr, int *nb_ip, Tokens *tokens,
                         int *i_ptr) {
    // 1. increment *i_ptr, make a copy of *nb_ip (=> start_ip)
    (*i_ptr)++;
    int start_ip = *nb_ip;

    // 2. call the function recursively
    get_rules_ip(ip_ptr, nb_ip, tokens, i_ptr);

    // 3. loop through the ips (start_ip -> *nb_ip) and inverse their negation
    for (int j = start_ip; j < *nb_ip; j++) {
        // inverse the ip's negation
        RuleIp *ip = (*ip_ptr) + j * sizeof(RuleIp);
        ip->negation = !ip->negation;
    }
}
void inverse_negation_port(RulePort **port_ptr, int *nb_ports, Tokens *tokens,
                           int *i_ptr) {
    // 1. increment *i_ptr, make a copy of *nb_ports (=> start_port)
    (*i_ptr)++;
    int start_port = *nb_ports;

    // 2. call the function recursively
    get_rules_port(port_ptr, nb_ports, tokens, i_ptr);

    // 3. loop through the ports (start_port -> *nb_ports) and inverse their
    // negation
    for (int j = start_port; j < *nb_ports; j++) {
        // inverse the port's negation
        RulePort *port = (*port_ptr) + j * sizeof(RulePort);
        port->negation = !port->negation;
    }
}
void get_ip_any(RuleIp **ip_ptr, int *nb_ip, Tokens *tokens, int *i_ptr) {
    // 1. increment *i_ptr, add a new ip
    (*i_ptr)++;
    increase_nb_ip(ip_ptr, nb_ip);
    RuleIp *ip = (*ip_ptr) + ((*nb_ip) - 1) * sizeof(RuleIp);

    // set the ip's fields
    ip->negation = false;
    ip->ip = -1;  // -1 => any

    // NOTE: we don't need to set a netmask because it's "any" ip
}
void get_port_any(RulePort **port_ptr, int *nb_ports, Tokens *tokens,
                  int *i_ptr) {
    // increment *i_ptr, add a new port
    (*i_ptr)++;
    increase_nb_ports(port_ptr, nb_ports);
    RulePort *port = (*port_ptr) + ((*nb_ports) - 1) * sizeof(RulePort);

    // set the port's fields
    port->negation = false;
    port->start_port = 0;
    port->end_port = -1;

    // NOTE: 0 to -1 => any
}
void get_ip_list(RuleIp **ip_ptr, int *nb_ip, Tokens *tokens, int *i_ptr) {
    // loop until we get the closing ']'
    while (strcmp(tokens->tokens[*i_ptr], "]") != 0) {
        // 1. increase *i_ptr, to pass the '[' or the ','
        (*i_ptr)++;
        // 2. call the function recursively to get the ip
        get_rules_ip(ip_ptr, nb_ip, tokens, i_ptr);
    }

    // for the closing ']'
    (*i_ptr)++;
}
void get_port_list(RulePort **port_ptr, int *nb_ports, Tokens *tokens,
                   int *i_ptr) {
    // loop until we get the closing ']'
    while (strcmp(tokens->tokens[*i_ptr], "]") != 0) {
        // 1. increase *i_ptr, to pass the '[' or the ','
        (*i_ptr)++;
        // 2. call the function recursively to get the port
        get_rules_port(port_ptr, nb_ports, tokens, i_ptr);
    }

    // for the closing ']'
    (*i_ptr)++;
}
void get_ip_address(RuleIp **ip_ptr, int *nb_ip, Tokens *tokens, int *i_ptr) {
    // 1. increment *i_ptr, add an ip to the list
    (*i_ptr)++;
    increase_nb_ip(ip_ptr, nb_ip);
    RuleIp *new_ip = &(*ip_ptr)[(*nb_ip) - 1];

    // 2. get the ip and the netmask
    new_ip->negation = false;
    get_ip_and_netmask_from_str(tokens->tokens[*i_ptr], &new_ip->ip,
                                &new_ip->netmask);
}
void get_port_address(RulePort **port_ptr, int *nb_ports, Tokens *tokens,
                      int *i_ptr) {
    // 1. increment *i_ptr, add a port to the list
    (*i_ptr)++;
    increase_nb_ports(port_ptr, nb_ports);
    RulePort *port = (*port_ptr) + ((*nb_ports) - 1) * sizeof(RulePort);

    // 2. get the port
    port->negation = false;
    get_port_from_str(port, tokens, i_ptr);
}


void get_rules_ip(RuleIp **ip_ptr, int *nb_ip, Tokens *tokens, int *i_ptr) {
    if (strcmp(tokens->tokens[*i_ptr], "!") == 0) {
        inverse_negation_ip(ip_ptr, nb_ip, tokens, i_ptr);
    } else if (strcmp(tokens->tokens[*i_ptr], "any") == 0) {
        get_ip_any(ip_ptr, nb_ip, tokens, i_ptr);
    } else if (strcmp(tokens->tokens[*i_ptr], "[") == 0) {
        get_ip_list(ip_ptr, nb_ip, tokens, i_ptr);
    } else {
        get_ip_address(ip_ptr, nb_ip, tokens, i_ptr);
    }
}
void get_rules_port(RulePort **port_ptr, int *nb_ports, Tokens *tokens,
                    int *i_ptr) {
    if (strcmp(tokens->tokens[*i_ptr], "!") == 0) {
        inverse_negation_port(port_ptr, nb_ports, tokens, i_ptr);
    } else if (strcmp(tokens->tokens[*i_ptr], "any") == 0) {
        get_port_any(port_ptr, nb_ports, tokens, i_ptr);
    } else if (strcmp(tokens->tokens[*i_ptr], "[") == 0) {
        get_port_list(port_ptr, nb_ports, tokens, i_ptr);
    } else {
        get_port_address(port_ptr, nb_ports, tokens, i_ptr);
    }
}

void get_rule_action(Rule *rule, Tokens *tokens, int *i_ptr) {
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

    (*i_ptr)++;
}
void get_rule_protocol(Rule *rule, Tokens *tokens, int *i_ptr) {
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

    (*i_ptr)++;
}
void get_rule_source_ip(Rule *rule, Tokens *tokens, int *i_ptr) {
    get_rules_ip(&rule->sources, &rule->nb_sources, tokens, i_ptr);
}
void get_rule_source_port(Rule *rule, Tokens *tokens, int *i_ptr) {
    get_rules_port(&rule->source_ports, &rule->nb_source_ports, tokens, i_ptr);
}
void get_rule_direction(Rule *rule, Tokens *tokens, int *i_ptr) {
    if (strcmp(tokens->tokens[*i_ptr], "->") == 0) {
        rule->direction = Forward;
    } else if (strcmp(tokens->tokens[*i_ptr], "<>") == 0) {
        rule->direction = Both_directions;
    }

    (*i_ptr)++;
}
void get_rule_destination_ip(Rule *rule, Tokens *tokens, int *i_ptr) {
    get_rules_ip(&rule->destinations, &rule->nb_destinations, tokens, i_ptr);
}
void get_rule_destination_port(Rule *rule, Tokens *tokens, int *i_ptr) {
    get_rules_port(&rule->destination_ports, &rule->nb_destination_ports,
                   tokens, i_ptr);
}
void get_rule_options(Rule *rule, Tokens *tokens, int *i_ptr) {
    // example of syntax: rule = ... (option:setting,setting;option:setting;)

    // increment because of the '('
    (*i_ptr)++;
    char *token = tokens->tokens[*i_ptr];

    // get all options
    while (strcmp(token, ")") != 0) {
        // add new option
        increase_nb_options(&rule->options, &rule->nb_options);
        RuleOption *option = &rule->options[rule->nb_options - 1];

        // initialize the new option
        option->keyword = NULL;
        option->settings = NULL;
        option->nb_settings = 0;

        // get option keyword
        copy_string_in_heap(token, &option->keyword);
        (*i_ptr)++;

        get_option_settings(option, tokens, i_ptr);

        token = tokens->tokens[*i_ptr];
    }

    // increment because of the ')'
    (*i_ptr)++;
}

void extract_rules(Rule **rules_ptr, int *nb_rules, Tokens *tokens) {
    int i = 0;
    while (i < tokens->nb_tokens) {
        // add an empty rule to the list
        increase_nb_rules(rules_ptr, nb_rules);
        Rule *rule = (*rules_ptr) + ((*nb_rules) - 1);

        // initialize the rule
        rule->nb_sources = 0;
        rule->nb_source_ports = 0;
        rule->nb_destinations = 0;
        rule->nb_destination_ports = 0;
        rule->nb_options = 0;
        rule->sources = NULL;
        rule->source_ports = NULL;
        rule->destinations = NULL;
        rule->destination_ports = NULL;
        rule->options = NULL;

        // get the rule
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


void read_rules(FILE *file, Rule **rules_ptr, int *count) {
    // 1. tokenize the text
    Tokens tokens = {NULL, 0};
    tokenize_rules(file, &tokens);

    // 2. close the file handle
    fclose(file);

    // 3. extract the rules
    extract_rules(rules_ptr, count, &tokens);

    // 4. free tokens
    for (size_t i = 0; i < tokens.nb_tokens; i++) {
        free(tokens.tokens[i]);
    }
    free(tokens.tokens);
}
