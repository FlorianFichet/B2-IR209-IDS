#include "error.h"


void print_error(Error_type error_type) {
    char error_message[100];

    switch (error_type) {
        case SNIFFER_ERROR_HANDLE_NOT_CREATED:
            strcpy(error_message, "Handle creation failure");
            break;
        case SNIFFER_ERROR_HANDLE_NOT_ACTIVATED:
            strcpy(error_message, "Failed handle activation");
            break;
        case RULES_FILE_NOT_OPENED_ERROR:
            strcpy(error_message, "Failure to open the rules file");
            break;
        case RULES_FILE_NOT_CLOSED_ERROR:
            strcpy(error_message, "Failure to close the rules file");
            break;
        default:
            break;
    }

    printf("\n!!! The IDS program encountered a problem : %s. !!!\n",
           error_message);
}
