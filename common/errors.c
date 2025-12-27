#include "errors.h"
#include <stdio.h>

const char* error_to_string(ErrorCode code) {
    switch (code) {
        case ERR_SUCCESS:
            return "Success";
        case ERR_FILE_NOT_FOUND:
            return "File not found";
        case ERR_FILE_EXISTS:
            return "File already exists";
        case ERR_ACCESS_DENIED:
            return "Access denied - you do not have permission to access this file";
        case ERR_INVALID_SENTENCE:
            return "Invalid sentence index - sentence number out of range";
        case ERR_INVALID_WORD_INDEX:
            return "Invalid word index - word position out of range";
        case ERR_SENTENCE_LOCKED:
            return "Sentence is locked by another user - please try again later";
        case ERR_SS_UNAVAILABLE:
            return "Storage server unavailable - the file server is not responding";
        case ERR_INVALID_COMMAND:
            return "Invalid command - please check your syntax";
        case ERR_CONNECTION_FAILED:
            return "Connection failed - unable to reach the server";
        case ERR_INTERNAL:
            return "Internal server error - please contact system administrator";
        case ERR_NOT_OWNER:
            return "Permission denied - only the file owner can perform this operation";
        case ERR_NETWORK_ERROR:
            return "Network error - connection lost or data transfer failed";
        case ERR_TIMEOUT:
            return "Operation timed out - server took too long to respond";
        case ERR_FILE_IN_USE:
            return "File is currently being modified by another user";
        case ERR_INVALID_PARAMS:
            return "Invalid parameters - please check your input";
        case ERR_QUOTA_EXCEEDED:
            return "Quota exceeded - storage limit reached";
        case ERR_CORRUPTED_DATA:
            return "Data corruption detected - file may be damaged";
        default:
            return "Unknown error";
    }
}
