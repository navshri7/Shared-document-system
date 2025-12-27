#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

#define MAX_FILENAME 256
#define MAX_USERNAME 64
#define MAX_PATH 512
#define MAX_CONTENT 4096
#define MAX_IP 16
#define BUFFER_SIZE 8192
#define MAX_ACL_STRING 1024

// Message types between components
typedef enum {
    // Client -> NM
    MSG_CLIENT_REGISTER,
    MSG_VIEW_FILES,
    MSG_READ_FILE,
    MSG_CREATE_FILE,
    MSG_WRITE_FILE,
    MSG_DELETE_FILE,
    MSG_INFO_FILE,
    MSG_STREAM_FILE,
    MSG_LIST_USERS,
    MSG_ADD_ACCESS,
    MSG_REM_ACCESS,
    MSG_REQUEST_ACCESS,
    MSG_LIST_ACCESS_REQUESTS,
    MSG_RESPOND_ACCESS_REQUEST,
    MSG_EXEC_FILE,
    MSG_UNDO_FILE,
    MSG_CREATE_FOLDER,
    MSG_MOVE_FILE,
    MSG_VIEW_FOLDER,
    MSG_CREATE_CHECKPOINT,
    MSG_LIST_CHECKPOINTS,
    MSG_REVERT_CHECKPOINT,
    MSG_VIEW_CHECKPOINT,
    // HISTORY
    MSG_HISTORY_REQUEST,    // Client -> NM (or NM -> SS) request for file history
    MSG_HISTORY_RESPONSE,   // NM (or SS) -> Client response with history entries
    
    // NM -> SS
    MSG_SS_CREATE_FILE,
    MSG_SS_DELETE_FILE,
    MSG_SS_CREATE_FOLDER,
    MSG_SS_MOVE_FILE,
    MSG_SS_GET_CONTENT,
    MSG_SS_GET_METADATA,
    MSG_SS_UPDATE_METADATA,
    MSG_SS_PULL_FILE, // NM -> SS: instruct SS to pull a file from another SS
    MSG_SS_CREATE_CHECKPOINT,
    MSG_SS_LIST_CHECKPOINTS,
    MSG_SS_REVERT_CHECKPOINT,
    MSG_SS_VIEW_CHECKPOINT,
    
    // SS -> NM
    MSG_SS_REGISTER,
    MSG_SS_ACK,
    MSG_SS_FILE_LIST,
    
    // Client <-> SS (direct)
    MSG_CLIENT_READ,
    MSG_CLIENT_WRITE,
    MSG_CLIENT_STREAM,

    MSG_PING,
    MSG_PONG,
    
    // Write operation sub-messages
    MSG_WRITE_START,      // Lock sentence and start write
    MSG_WRITE_UPDATE,     // Update word at index
    MSG_WRITE_END,        // Unlock sentence and commit
    
    // Responses
    MSG_SUCCESS,
    MSG_ERROR,
    MSG_REDIRECT,      // NM tells client to connect to SS
    MSG_STOP           // End of streaming
} MessageType;

// Generic message header
typedef struct {
    MessageType type;
    uint32_t length;    // Length of payload
    uint32_t seq_num;   // Sequence number for reliability
} MessageHeader;

// Client registration
typedef struct {
    char username[MAX_USERNAME];
    char ip[MAX_IP];
    uint16_t nm_port;
    uint16_t ss_port;
} ClientRegisterMsg;

// Storage Server registration
typedef struct {
    char ip[MAX_IP];
    uint16_t nm_port;
    uint16_t client_port;
    int num_files;
    // Followed by array of filenames
} SSRegisterMsg;

// File operation request
typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME];
} FileOpMsg;

// Write start request (locks sentence)
typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME];
    int sentence_num;
} WriteStartMsg;

// Write update request (modify word)
typedef struct {
    char filename[MAX_FILENAME];
    int sentence_num;
    int word_index;
    char content[MAX_CONTENT];
} WriteUpdateMsg;

// Write end request (unlocks sentence)
typedef struct {
    char filename[MAX_FILENAME];
    int sentence_num;
} WriteEndMsg;

// Access control
typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME];
    char target_user[MAX_USERNAME];
    bool read_access;
    bool write_access;
} AccessMsg;

// Redirect message (NM -> Client)
typedef struct {
    char ss_ip[MAX_IP];
    uint16_t ss_port;
} RedirectMsg;

// Error response
typedef struct {
    int error_code;
    char message[256];
} ErrorMsg;

// VIEW request
typedef struct {
    char username[MAX_USERNAME];
    bool show_all;      // -a flag
    bool show_details;  // -l flag
} ViewMsg;

// File info for VIEW response
typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    int word_count;
    int char_count;
    char last_access[64];
    char created[64];
} FileInfo;

typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    time_t created;
    time_t last_modified;
    time_t last_accessed;
    size_t size;
    int word_count;
    int char_count;
    char read_users[MAX_ACL_STRING];  // Comma-separated list of users
    char write_users[MAX_ACL_STRING]; // Comma-separated list of users
} SSMetadataTransferMsg;

// Instruct a storage server to pull a file from another storage server
typedef struct {
    char filename[MAX_FILENAME];
    char src_ip[MAX_IP];    // IP of source SS
    uint16_t src_port;      // client port of source SS
} SSReplicateMsg;

// Folder messages
typedef struct {
    char foldername[MAX_PATH];
    char username[MAX_USERNAME];
} CreateFolderMsg;

typedef struct {
    char src[MAX_PATH];
    char dst[MAX_PATH];
    char username[MAX_USERNAME];
} MoveFileMsg;

typedef struct {
    char foldername[MAX_PATH];
    char username[MAX_USERNAME];
} ViewFolderMsg;

// Checkpoint messages
typedef struct {
    char filename[MAX_FILENAME];
    char tag[64];
    char username[MAX_USERNAME];
} CheckpointMsg;

typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME];
} CheckpointListReq;

// History request: ask for last N entries for a file
typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME];
    int max_entries; // if <=0, server may use a default like 10
} HistoryReq;

// Single history entry describing an edit
typedef struct {
    char timestamp[64];      // human-readable timestamp
    char username[MAX_USERNAME];
    char op_type[32];        // e.g., "create", "write", "delete", "revert", "checkpoint", "undo"
    int lines_added;
    int lines_removed;
    int chars_added;
    int chars_removed;
    char comment[256];       // optional short description
} HistoryEntry;

// History response: array of HistoryEntry, serialized as consecutive entries
typedef struct {
    int entries_count;
    // Followed by `entries_count` HistoryEntry structures in payload
} HistoryResp;

// Access request messages
typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME]; // requester
} RequestAccessMsg;

typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME]; // owner requesting the list
} AccessListReq;

// Owner's response to a pending access request
typedef struct {
    char filename[MAX_FILENAME];
    char username[MAX_USERNAME]; // owner
    char target_user[MAX_USERNAME]; // requester being responded to
    bool approve;   // true = approve, false = deny
    bool grant_write; // if approving, grant write access when true, otherwise grant read-only
} AccessResponseMsg;

// Checkpoint list response: payload is newline-separated tags
// Revert uses CheckpointMsg as request


#endif 
