#ifndef ERROR_H
#define ERROR_H


#include <stdio.h>
#include <string.h>


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


void print_error(Error_type error_type);


#endif // ERROR_H
