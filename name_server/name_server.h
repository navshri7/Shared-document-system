#ifndef NAME_SERVER_H
#define NAME_SERVER_H

#include "../common/protocol.h"
#include <pthread.h>

// Storage Server info
typedef struct StorageServer {
    char ip[MAX_IP];
    uint16_t nm_port;
    uint16_t client_port;
    int sockfd;
    bool active;
    time_t last_heartbeat; // last time we successfully talked to this SS
    
    char** files;
    int num_files;
    
    pthread_mutex_t socket_mutex;  // Serialize access to sockfd
    
    struct StorageServer* next;
} StorageServer;

// Client info
typedef struct Client {
    char username[MAX_USERNAME];
    char ip[MAX_IP];
    int sockfd;
    bool active;
    struct Client* next;
} Client;

// Search cache entry (LRU cache for recent file lookups)
typedef struct CacheEntry {
    char filename[MAX_FILENAME];
    void* file_meta;  // FileMetadata*
    time_t last_access;
    struct CacheEntry* next;
    struct CacheEntry* prev;
} CacheEntry;

// Search cache (LRU with max 100 entries)
typedef struct {
    CacheEntry* head;  // Most recently used
    CacheEntry* tail;  // Least recently used
    int size;
    int max_size;
    pthread_mutex_t cache_lock;
} SearchCache;

// Name Server state
typedef struct {
    StorageServer* ss_list;
    Client* client_list;
    pthread_mutex_t ss_lock;
    pthread_mutex_t client_lock;
    pthread_mutex_t file_index_lock; // protect file index & metadata ops
    
    // For efficient search (implement Trie or HashMap here)
    void* file_index;    // Points to your search data structure
    
    // Search cache for frequently accessed files
    SearchCache* search_cache;
    
    uint16_t nm_port;
    int server_sockfd;
} NameServer;

// Core functions
int nm_init(NameServer* nm, uint16_t port);
void nm_start(NameServer* nm);
void* handle_client_connection(void* arg);
void* handle_ss_connection(void* arg);

// Storage Server management
int register_storage_server(NameServer* nm, SSRegisterMsg* msg, int sockfd);
StorageServer* find_ss_for_file(NameServer* nm, const char* filename);

// Client management
int register_client(NameServer* nm, ClientRegisterMsg* msg, int sockfd);
Client* find_client(NameServer* nm, const char* username);

// Request handlers
void handle_view_files(NameServer* nm, int client_fd, ViewMsg* msg);
void handle_create_file(NameServer* nm, int client_fd, FileOpMsg* msg);
void handle_delete_file(NameServer* nm, int client_fd, FileOpMsg* msg);
void handle_file_info(NameServer* nm, int client_fd, FileOpMsg* msg);
void handle_list_users(NameServer* nm, int client_fd);
void handle_access_control(NameServer* nm, int client_fd, AccessMsg* msg);
void handle_exec(NameServer* nm, int client_fd, FileOpMsg* msg);
void handle_create_checkpoint(NameServer* nm, int client_fd, CheckpointMsg* msg);
void handle_list_checkpoints(NameServer* nm, int client_fd, CheckpointListReq* msg);
void handle_revert_checkpoint(NameServer* nm, int client_fd, CheckpointMsg* msg);

// Access request workflow
void handle_request_access(NameServer* nm, int client_fd, RequestAccessMsg* msg);
void handle_list_access_requests(NameServer* nm, int client_fd, AccessListReq* msg);
void handle_respond_access_request(NameServer* nm, int client_fd, AccessResponseMsg* msg);

#endif // NAME_SERVER_H
