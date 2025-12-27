#ifndef FILE_OPS_H
#define FILE_OPS_H

// Forward declaration
struct StorageServer;

// Core file operations
int ss_create_file(struct StorageServer* ss, const char* filename);
int ss_read_file(struct StorageServer* ss, const char* filename, char** content);
int ss_delete_file(struct StorageServer* ss, const char* filename);
int ss_undo_file(struct StorageServer* ss, const char* filename);

// Write operations (multi-step with locking)
int ss_write_start(struct StorageServer* ss, const char* filename, int sentence_num, const char* username);
int ss_write_update(struct StorageServer* ss, const char* filename, int sentence_num, 
                    int word_index, const char* content);
int ss_write_end(struct StorageServer* ss, const char* filename, int sentence_num);

// Sentence locking
int acquire_sentence_lock(struct StorageServer* ss, const char* filename, 
                         int sentence_num, const char* username);
int release_sentence_lock(struct StorageServer* ss, const char* filename, int sentence_num);

// Streaming
void ss_stream_file(struct StorageServer* ss, int client_fd, const char* filename);

#endif // FILE_OPS_H

