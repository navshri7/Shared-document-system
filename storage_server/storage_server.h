#ifndef STORAGE_SERVER_H
#define STORAGE_SERVER_H

#include "../common/protocol.h"
#include <pthread.h>
#include <time.h>

// File metadata stored on storage server (persistent)
typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    time_t created;
    time_t last_modified;
    time_t last_accessed;
    size_t size;
    int word_count;
    int char_count;
    
    // Access control
    char** read_users;
    int num_read_users;
    char** write_users;
    int num_write_users;
} SSFileMetadata;

// Sentence lock for concurrent write handling
typedef struct {
    char filename[MAX_FILENAME];
    int sentence_num;
    
    bool in_use;                // Whether this lock slot is in the array
    bool locked;                // The "fail-fast" flag: is a client editing this?
    char locked_by[MAX_USERNAME];
    time_t locked_at;           // For deadlock/abandoned lock detection
} SentenceLock;

// Per-file commit mutex
typedef struct {
    char filename[MAX_FILENAME];
    pthread_mutex_t mutex;
    bool in_use;
} FileCommitMutex;

// Storage Server state
typedef struct StorageServer {
    char ip[MAX_IP];
    uint16_t nm_port;
    uint16_t client_port;
    int nm_sockfd;           // Connection to Name Server
    int client_server_fd;    // Socket for client connections
    char storage_path[MAX_PATH];  // Base directory for files
    
    SentenceLock* locks;
    int num_locks;
    // *** This global mutex protects the 'locks' array itself (when adding/removing entries) ***
    pthread_mutex_t locks_mutex;
    
    // Per-file commit mutexes for atomic commits
    FileCommitMutex* file_commit_mutexes;
    int num_file_commit_mutexes;
    pthread_mutex_t file_commit_mutexes_mutex;  // Protects the array itself
    
    // Undo support (store previous version)
    struct {
        char filename[MAX_FILENAME];
        char* prev_content;
        bool has_backup;
    } undo_state[100];  // Support undo for up to 100 files
    
    // File metadata cache (loaded from disk)
    SSFileMetadata* file_metadata;
    int num_metadata;
    pthread_mutex_t metadata_mutex;  // Protects metadata array
} StorageServer;

// Core functions
int ss_init(StorageServer* ss, const char* nm_ip, uint16_t nm_port, uint16_t client_port);
int ss_register_with_nm(StorageServer* ss);
void ss_start(StorageServer* ss);
void* handle_nm_requests(void* arg);
void* handle_client_requests(void* arg);

// Persistence functions
int ss_save_undo_state(StorageServer* ss, int undo_idx);
int ss_load_undo_states(StorageServer* ss);
int ss_save_file_metadata(StorageServer* ss, const char* filename, SSFileMetadata* meta);
int ss_load_file_metadata(StorageServer* ss);
SSFileMetadata* ss_get_file_metadata(StorageServer* ss, const char* filename);
int ss_update_file_metadata(StorageServer* ss, const char* filename, const char* owner, 
                            int word_count, int char_count, size_t size);

#endif // STORAGE_SERVER_H