#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include "file_manager.h"

bool can_read_file(FileMetadata* meta, const char* username);
bool can_write_file(FileMetadata* meta, const char* username);
bool is_owner(FileMetadata* meta, const char* username);
int grant_access(FileMetadata* meta, const char* username, bool read, bool write);
int revoke_access(FileMetadata* meta, const char* username);

#endif // ACCESS_CONTROL_H
