#include "access_control.h"
#include <string.h>

bool can_read_file(FileMetadata* meta, const char* username) {
    return check_read_access(meta, username);
}

bool can_write_file(FileMetadata* meta, const char* username) {
    return check_write_access(meta, username);
}

bool is_owner(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return false;
    return strcmp(meta->owner, username) == 0;
}

int grant_access(FileMetadata* meta, const char* username, bool read, bool write) {
    if (meta == NULL || username == NULL) return -1;
    
    if (write) {
        add_write_access(meta, username);
    } else if (read) {
        add_read_access(meta, username);
    }
    
    return 0;
}

int revoke_access(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return -1;
    
    remove_access(meta, username);
    return 0;
}
