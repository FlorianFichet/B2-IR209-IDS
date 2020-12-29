#pragma once

#include <stdio.h>

enum error_type {
    not_error,
    SNIFFER_ERROR_HANDLE_NOT_CREATED,
    SNIFFER_ERROR_HANDLE_NOT_ACTIVATED,
    RULES_FILE_NOT_OPENED_ERROR,
    RULES_FILE_NOT_CLOSED_ERROR,

} typedef Error_type;

struct error {
    Error_type type;
    char* error_message;

} typedef Error;

Error handle_not_created = {SNIFFER_ERROR_HANDLE_NOT_CREATED, "Handle creation failure"};
Error handle_not_activated = {SNIFFER_ERROR_HANDLE_NOT_ACTIVATED, "Failed handle activation"};
Error rules_file_not_opened = {RULES_FILE_NOT_OPENED_ERROR, "Failure to open the rules file"};
Error rules_file_not_closed = {RULES_FILE_NOT_CLOSED_ERROR, "Failure to close the rules file"};

void print_error (Error error_ids){
    printf("\n!!! The IDS program encountered a problem : %s. !!!\n", error_ids.error_message);
}