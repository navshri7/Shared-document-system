#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "../common/protocol.h"
#include <time.h>
#include <pthread.h>

// Forward declaration
typedef struct StorageServer StorageServer;

#define ACL_HASH_BUCKETS 64

typedef struct ACLHashNode {
    char username[MAX_USERNAME];
    struct ACLHashNode* next;
} ACLHashNode;

typedef struct {
    ACLHashNode* buckets[ACL_HASH_BUCKETS];
} ACLHashTable;

// File metadata
typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    time_t created;
    time_t last_modified;
    time_t last_accessed;
    size_t size;
    int word_count;
    int char_count;
    bool is_folder;
    
    // Access control
    char** read_users;
    int num_read_users;
    ACLHashTable read_index;
    char** write_users;
    int num_write_users;
    ACLHashTable write_index;
    // Pending access requests (list of requester usernames)
    char** access_requests;
    int num_access_requests;
    // Mutex to protect metadata fields (ACLs, counts, timestamps)
    pthread_mutex_t meta_lock;
    
    // Location
    StorageServer* primary_ss;
    // Replica pointer (best-effort redundant copy)
    StorageServer* replica_ss;
} FileMetadata;

// Efficient search structure (Trie/HashMap)
typedef struct TrieNode {
    struct TrieNode* children[256];
    FileMetadata* file_meta;
    bool is_end;
} TrieNode;
// CAN BE CHANGED JUST THERE FOR NOW 

// File index operations
TrieNode* create_trie_node();
void insert_file(TrieNode* root, const char* filename, FileMetadata* meta);
FileMetadata* search_file(TrieNode* root, const char* filename);
void delete_file_from_trie(TrieNode* root, const char* filename);
void collect_all_files(TrieNode* root, FileMetadata*** files, int* count, const char* prefix);
// Folder operations
bool create_folder(TrieNode* root, const char* foldername, const char* owner);
bool move_file(TrieNode* root, const char* src, const char* dst);

// Metadata operations
FileMetadata* create_file_metadata(const char* filename, const char* owner);
void update_file_access_time(FileMetadata* meta);
bool check_read_access(FileMetadata* meta, const char* username);
bool check_write_access(FileMetadata* meta, const char* username);
// Variants that assume the caller already holds the file-index lock and therefore
// must NOT attempt to acquire meta_lock (avoids lock-order inversion).
bool check_read_access_nolock(FileMetadata* meta, const char* username);
bool check_write_access_nolock(FileMetadata* meta, const char* username);
void add_read_access(FileMetadata* meta, const char* username);
void add_write_access(FileMetadata* meta, const char* username);
void remove_access(FileMetadata* meta, const char* username);

// Access request helpers
void add_access_request(FileMetadata* meta, const char* requester);
// Writes a newline-separated list of pending requesters into outbuf (buflen bytes)
void list_access_requests_string(FileMetadata* meta, char* outbuf, size_t buflen);
void remove_access_request(FileMetadata* meta, const char* requester);

#endif // FILE_MANAGER_H
