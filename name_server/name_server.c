#include "name_server.h"
#include "file_manager.h"
#include "access_control.h"
#include "../common/utils.h"
#include "../common/protocol.h"
#include "../common/errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>

// Helper function to send error messages
static void send_error(int client_fd, ErrorCode error_code, uint32_t seq_num) {
    ErrorMsg error;
    error.error_code = error_code;
    strncpy(error.message, error_to_string(error_code), sizeof(error.message) - 1);
    error.message[sizeof(error.message) - 1] = '\0';
    
    MessageHeader resp_header;
    resp_header.type = MSG_ERROR;
    resp_header.length = sizeof(ErrorMsg);
    resp_header.seq_num = seq_num;
    
    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
    send(client_fd, &error, sizeof(ErrorMsg), 0);
    
}

// Move a cache entry to the front (most-recently-used)
static void cache_move_to_front(SearchCache* cache, CacheEntry* entry) {
    if (entry == cache->head) return;  // Already at front

    // Remove from current position
    if (entry->prev) entry->prev->next = entry->next;
    if (entry->next) entry->next->prev = entry->prev;
    if (entry == cache->tail) cache->tail = entry->prev;

    // Move to front
    entry->prev = NULL;
    entry->next = cache->head;
    if (cache->head) cache->head->prev = entry;
    cache->head = entry;
    if (cache->tail == NULL) cache->tail = entry;
}
static FileMetadata* cache_get(SearchCache* cache, const char* filename) {
    pthread_mutex_lock(&cache->cache_lock);
    
    CacheEntry* curr = cache->head;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            curr->last_access = time(NULL);
            cache_move_to_front(cache, curr);
            FileMetadata* result = (FileMetadata*)curr->file_meta;
            pthread_mutex_unlock(&cache->cache_lock);
            return result;
        }
        curr = curr->next;
    }
    
    pthread_mutex_unlock(&cache->cache_lock);
    return NULL;
}

static void cache_put(SearchCache* cache, const char* filename, FileMetadata* meta) {
    pthread_mutex_lock(&cache->cache_lock);
    
    // Create new entry
    CacheEntry* entry = (CacheEntry*)malloc(sizeof(CacheEntry));
    strncpy(entry->filename, filename, MAX_FILENAME - 1);
    entry->filename[MAX_FILENAME - 1] = '\0';
    entry->file_meta = meta;
    entry->last_access = time(NULL);
    entry->prev = NULL;
    entry->next = cache->head;
    
    if (cache->head) cache->head->prev = entry;
    cache->head = entry;
    if (cache->tail == NULL) cache->tail = entry;
    cache->size++;
    
    // Evict LRU if cache is full
    if (cache->size > cache->max_size) {
        CacheEntry* lru = cache->tail;
        cache->tail = lru->prev;
        if (cache->tail) cache->tail->next = NULL;
        free(lru);
        cache->size--;
    }
    
    pthread_mutex_unlock(&cache->cache_lock);
}

static void cache_invalidate(SearchCache* cache, const char* filename) {
    pthread_mutex_lock(&cache->cache_lock);
    
    CacheEntry* curr = cache->head;
    while (curr != NULL) {
        if (strcmp(curr->filename, filename) == 0) {
            if (curr->prev) curr->prev->next = curr->next;
            if (curr->next) curr->next->prev = curr->prev;
            if (curr == cache->head) cache->head = curr->next;
            if (curr == cache->tail) cache->tail = curr->prev;
            free(curr);
            cache->size--;
            break;
        }
        curr = curr->next;
    }
    
    pthread_mutex_unlock(&cache->cache_lock);
}

// Cached search function
static FileMetadata* search_file_cached(NameServer* nm, const char* filename) {
    // Try cache first
    FileMetadata* cached = cache_get(nm->search_cache, filename);
    if (cached != NULL) {
        log_message("NM", "Cache HIT for %s", filename);
        return cached;
    }
    
    // Cache miss - search trie
    log_message("NM", "Cache MISS for %s - searching trie", filename);
    FileMetadata* meta = search_file((TrieNode*)nm->file_index, filename);
    
    // Add to cache if found
    if (meta != NULL) {
        cache_put(nm->search_cache, filename, meta);
    }
    
    return meta;
}

// Check if user is registered
static bool is_user_registered(NameServer* nm, const char* username) {
    pthread_mutex_lock(&nm->client_lock);
    
    Client* client = nm->client_list;
    while (client != NULL) {
        if (strcmp(client->username, username) == 0) {
            pthread_mutex_unlock(&nm->client_lock);
            return true;
        }
        client = client->next;
    }
    
    pthread_mutex_unlock(&nm->client_lock);
    return false;
}

// Initialize Name Server
int nm_init(NameServer* nm, uint16_t port) {
    if (nm == NULL) return -1;
    
    nm->ss_list = NULL;
    nm->client_list = NULL;
    nm->nm_port = port;
    nm->server_sockfd = -1;
    
    pthread_mutex_init(&nm->ss_lock, NULL);
    pthread_mutex_init(&nm->client_lock, NULL);
    pthread_mutex_init(&nm->file_index_lock, NULL);
    
    // Initialize file index (Trie)
    nm->file_index = (void*)create_trie_node();
    
    // Initialize search cache
    nm->search_cache = (SearchCache*)malloc(sizeof(SearchCache));
    nm->search_cache->head = NULL;
    nm->search_cache->tail = NULL;
    nm->search_cache->size = 0;
    nm->search_cache->max_size = 100;  // Cache up to 100 recent searches
    pthread_mutex_init(&nm->search_cache->cache_lock, NULL);
    
    log_message("NM", "Name Server initialized on port %d with LRU cache (max 100 entries)", port);
    return 0;
}

// Register Storage Server
int register_storage_server(NameServer* nm, SSRegisterMsg* msg, int sockfd) {
    pthread_mutex_lock(&nm->ss_lock);
    
    // Check if SS with same client_port already exists (reconnection scenario)
    StorageServer* existing = nm->ss_list;
    while (existing != NULL) {
        if (existing->client_port == msg->client_port) {
            // Found existing SS - reactivate it instead of creating duplicate
            log_message("NM", "SS at port %d reconnecting - reactivating existing entry", msg->client_port);
            
            // Update connection info
            existing->sockfd = sockfd;
            existing->active = true;
            existing->last_heartbeat = time(NULL);
            strncpy(existing->ip, msg->ip, MAX_IP - 1);
            existing->ip[MAX_IP - 1] = '\0';
            // Note: socket_mutex already initialized from first registration
            
            // Free old file list
            for (int i = 0; i < existing->num_files; i++) {
                free(existing->files[i]);
            }
            free(existing->files);
            
            // Allocate new file list
            existing->num_files = msg->num_files;
            existing->files = (char**)malloc(msg->num_files * sizeof(char*));
            for (int i = 0; i < msg->num_files; i++) {
                existing->files[i] = (char*)malloc(MAX_FILENAME);
            }
            
            pthread_mutex_unlock(&nm->ss_lock);
            log_message("NM", "Reactivated SS at %s:%d with %d files (fd=%d)", 
                       existing->ip, existing->client_port, msg->num_files, sockfd);
            return 0;
        }
        existing = existing->next;
    }
    
    // No existing SS found - create new one
    StorageServer* ss = (StorageServer*)malloc(sizeof(StorageServer));
    if (ss == NULL) {
        pthread_mutex_unlock(&nm->ss_lock);
        return -1;
    }
    
    strncpy(ss->ip, msg->ip, MAX_IP - 1);
    ss->ip[MAX_IP - 1] = '\0';
    ss->nm_port = msg->nm_port;
    ss->client_port = msg->client_port;
    ss->sockfd = sockfd;
    ss->active = true;
    ss->last_heartbeat = time(NULL);
    ss->num_files = msg->num_files;
    pthread_mutex_init(&ss->socket_mutex, NULL);  // Initialize socket mutex
    
    
    // Allocate file list
    ss->files = (char**)malloc(msg->num_files * sizeof(char*));
    for (int i = 0; i < msg->num_files; i++) {
        ss->files[i] = (char*)malloc(MAX_FILENAME);
    }
    
    // Add to list
    ss->next = nm->ss_list;
    nm->ss_list = ss;
    
    pthread_mutex_unlock(&nm->ss_lock);
    
    log_message("NM", "Registered new SS at %s:%d with %d files (fd=%d)", 
                ss->ip, ss->client_port, msg->num_files, sockfd);
    
    return 0;
}

// Find Storage Server for file
StorageServer* find_ss_for_file(NameServer* nm, const char* filename) {
    pthread_mutex_lock(&nm->ss_lock);
    
    StorageServer* ss = nm->ss_list;
    while (ss != NULL) {
        if (!ss->active) {
            ss = ss->next;
            continue;
        }
        
        for (int i = 0; i < ss->num_files; i++) {
            if (strcmp(ss->files[i], filename) == 0) {
                pthread_mutex_unlock(&nm->ss_lock);
                return ss;
            }
        }
        ss = ss->next;
    }
    
    pthread_mutex_unlock(&nm->ss_lock);
    return NULL;
}

// Register Client
int register_client(NameServer* nm, ClientRegisterMsg* msg, int sockfd) {
    pthread_mutex_lock(&nm->client_lock);
    
    // Check if client with same username already exists and mark old ones inactive
    Client* curr = nm->client_list;
    while (curr != NULL) {
        if (strcmp(curr->username, msg->username) == 0 && curr->active) {
            // Mark old client as inactive (they reconnected)
            log_message("NM", "Marking old client entry for %s as inactive (socket %d)", 
                       curr->username, curr->sockfd);
            curr->active = false;
        }
        curr = curr->next;
    }
    
    Client* client = (Client*)malloc(sizeof(Client));
    if (client == NULL) {
        pthread_mutex_unlock(&nm->client_lock);
        return -1;
    }
    
    strncpy(client->username, msg->username, MAX_USERNAME - 1);
    client->username[MAX_USERNAME - 1] = '\0';
    strncpy(client->ip, msg->ip, MAX_IP - 1);
    client->ip[MAX_IP - 1] = '\0';
    client->sockfd = sockfd;
    client->active = true;
    
    // Add to list
    client->next = nm->client_list;
    nm->client_list = client;
    
    pthread_mutex_unlock(&nm->client_lock);
    
    log_message("NM", "Registered client: %s from %s (socket %d)", client->username, client->ip, sockfd);
    
    return 0;
}

// Find client by username
Client* find_client(NameServer* nm, const char* username) {
    pthread_mutex_lock(&nm->client_lock);
    
    Client* client = nm->client_list;
    while (client != NULL) {
        if (strcmp(client->username, username) == 0 && client->active) {
            pthread_mutex_unlock(&nm->client_lock);
            return client;
        }
        client = client->next;
    }
    
    pthread_mutex_unlock(&nm->client_lock);
    return NULL;
}

// Thread argument structure
typedef struct {
    NameServer* nm;
    int sockfd;
} ThreadArg;

// Forward declarations for background threads
void* nm_health_check_thread(void* arg);
void* nm_replication_thread(void* arg);

// Remove client from list
static void remove_client(NameServer* nm, int sockfd) {
    pthread_mutex_lock(&nm->client_lock);
    
    Client* prev = NULL;
    Client* curr = nm->client_list;
    
    while (curr != NULL) {
        if (curr->sockfd == sockfd) {
            if (prev == NULL) {
                nm->client_list = curr->next;
            } else {
                prev->next = curr->next;
            }
            curr->active = false;
            log_message("NM", "Removed client %s (socket %d) from list", curr->username, sockfd);
            free(curr);
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    
    pthread_mutex_unlock(&nm->client_lock);
}

// Handle client connection
void* handle_client_connection(void* arg) {
    ThreadArg* targ = (ThreadArg*)arg;
    int client_fd = targ->sockfd;
    NameServer* nm = targ->nm;
    free(targ);
    
    MessageHeader header;
    char buffer[BUFFER_SIZE];
    
    while (1) {
        int recv_result = recv(client_fd, &header, sizeof(MessageHeader), MSG_WAITALL);
        if (recv_result <= 0) {
            if (recv_result < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
                log_message("NM", "Client connection timed out (socket %d)", client_fd);
            } else if (recv_result == 0) {
                log_message("NM", "Client disconnected normally (socket %d)", client_fd);
            } else {
                log_error("NM", "Client connection error (socket %d): %s", client_fd, strerror(errno));
            }
            remove_client(nm, client_fd);
            close(client_fd);
            break;
        }
        
        log_message("NM", "Received message type %d from client (fd=%d)", header.type, client_fd);
        
        // Receive payload
        if (header.length > 0) {
            if (header.length >= BUFFER_SIZE) {
                log_error("NM", "Message too large: %d bytes (fd=%d)", header.length, client_fd);
                continue;
            }
            
            int recv_payload = recv(client_fd, buffer, header.length, MSG_WAITALL);
            if (recv_payload != (ssize_t)header.length) {
                log_error("NM", "Failed to receive complete payload (fd=%d): expected %d, got %d", 
                         client_fd, header.length, recv_payload);
                continue;
            }
        }
        
        // Handle message types
        switch (header.type) {
            case MSG_CLIENT_REGISTER: {
                ClientRegisterMsg* msg = (ClientRegisterMsg*)buffer;
                int result = register_client(nm, msg, client_fd);
                
                MessageHeader resp_header;
                resp_header.type = (result == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp_header.length = 0;
                resp_header.seq_num = header.seq_num;
                
                ssize_t sent = send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                if (sent != sizeof(MessageHeader)) {
                    log_error("NM", "Failed to send registration response: %d", (int)sent);
                } else {
                    log_message("NM", "Sent registration response to client (fd=%d)", client_fd);
                }
                break;
            }
            
            case MSG_CREATE_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                handle_create_file(nm, client_fd, msg);
                break;
            }
            
            case MSG_VIEW_FILES: {
                ViewMsg* msg = (ViewMsg*)buffer;
                handle_view_files(nm, client_fd, msg);
                break;
            }

            case MSG_CREATE_FOLDER: {
                CreateFolderMsg* msg = (CreateFolderMsg*)buffer;
                log_message("NM", "CREATE_FOLDER request for %s by %s (fd=%d)", msg->foldername, msg->username, client_fd);

                // Create folder in name index
                pthread_mutex_lock(&nm->file_index_lock);
                bool created = create_folder((TrieNode*)nm->file_index, msg->foldername, msg->username);
                pthread_mutex_unlock(&nm->file_index_lock);

                MessageHeader resp;
                resp.type = created ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                resp.seq_num = header.seq_num;
                send(client_fd, &resp, sizeof(MessageHeader), 0);

                if (created) {
                    // Inform all storage servers to create corresponding directory (best-effort)
                    pthread_mutex_lock(&nm->ss_lock);
                    int ss_count = 0;
                    for (StorageServer* s = nm->ss_list; s != NULL; s = s->next) if (s->active) ss_count++;
                    StorageServer** ss_arr = NULL;
                    if (ss_count > 0) {
                        ss_arr = (StorageServer**)malloc(ss_count * sizeof(StorageServer*));
                        int idx = 0;
                        for (StorageServer* s = nm->ss_list; s != NULL; s = s->next) {
                            if (!s->active) continue;
                            ss_arr[idx++] = s;
                        }
                    }
                    pthread_mutex_unlock(&nm->ss_lock);

                    if (ss_arr) {
                        CreateFolderMsg cfmsg;
                        strncpy(cfmsg.foldername, msg->foldername, MAX_PATH - 1);
                        cfmsg.foldername[MAX_PATH - 1] = '\0';
                        strncpy(cfmsg.username, msg->username, MAX_USERNAME - 1);
                        cfmsg.username[MAX_USERNAME - 1] = '\0';

                        MessageHeader req = { .type = MSG_SS_CREATE_FOLDER, .length = sizeof(CreateFolderMsg), .seq_num = 0 };
                        for (int i = 0; i < ss_count; i++) {
                            StorageServer* s = ss_arr[i];
                            pthread_mutex_lock(&s->socket_mutex);
                            if (send_with_retry(s->sockfd, &req, sizeof(MessageHeader), MAX_RETRIES) == 0 &&
                                send_with_retry(s->sockfd, &cfmsg, sizeof(CreateFolderMsg), MAX_RETRIES) == 0) {
                                MessageHeader ack;
                                if (recv_with_timeout(s->sockfd, &ack, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
                                    log_error("NM", "Timeout waiting for folder ack from SS %s:%d", s->ip, s->client_port);
                                }
                            } else {
                                log_error("NM", "Failed to notify SS %s:%d about folder create", s->ip, s->client_port);
                            }
                            pthread_mutex_unlock(&s->socket_mutex);
                        }
                        free(ss_arr);
                    }
                }
                break;
            }

            case MSG_VIEW_FOLDER: {
                ViewFolderMsg* msg = (ViewFolderMsg*)buffer;
                log_message("NM", "VIEW_FOLDER request for %s by %s (fd=%d)", msg->foldername, msg->username, client_fd);

                // Normalize prefix to include trailing slash
                char prefix[MAX_FILENAME];
                strncpy(prefix, msg->foldername, MAX_FILENAME - 2);
                prefix[MAX_FILENAME - 2] = '\0';
                int len = strlen(prefix);
                if (len == 0 || prefix[len-1] != '/') {
                    strncat(prefix, "/", 2);
                }

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata** matches = NULL;
                int match_count = 0;
                collect_all_files((TrieNode*)nm->file_index, &matches, &match_count, prefix);

                // Filter by access and prepare FileInfo array
                FileInfo* file_list = (FileInfo*)malloc(match_count * sizeof(FileInfo));
                int accessible_count = 0;
                for (int i = 0; i < match_count; i++) {
                    FileMetadata* m = matches[i];
                    if (!check_read_access_nolock(m, msg->username)) continue;
                    FileInfo* info = &file_list[accessible_count];
                    strncpy(info->filename, m->filename, MAX_FILENAME - 1);
                    info->filename[MAX_FILENAME - 1] = '\0';
                    strncpy(info->owner, m->owner, MAX_USERNAME - 1);
                    info->owner[MAX_USERNAME - 1] = '\0';
                    info->word_count = m->word_count;
                    info->char_count = m->char_count;
                    strftime(info->last_access, sizeof(info->last_access), "%Y-%m-%d %H:%M", localtime(&m->last_accessed));
                    strftime(info->created, sizeof(info->created), "%Y-%m-%d %H:%M", localtime(&m->created));
                    accessible_count++;
                }
                pthread_mutex_unlock(&nm->file_index_lock);

                MessageHeader resp;
                resp.type = MSG_SUCCESS;
                resp.length = accessible_count * sizeof(FileInfo);
                resp.seq_num = 0;
                send(client_fd, &resp, sizeof(MessageHeader), 0);
                if (accessible_count > 0) send(client_fd, file_list, resp.length, 0);

                free(matches);
                free(file_list);
                break;
            }

            case MSG_CREATE_CHECKPOINT: {
                CheckpointMsg* msg = (CheckpointMsg*)buffer;
                log_message("NM", "CREATE_CHECKPOINT request %s tag=%s by %s", msg->filename, msg->tag, msg->username);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                pthread_mutex_unlock(&nm->file_index_lock);

                if (meta == NULL) {
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }

                StorageServer* ss = meta->primary_ss;
                if (ss == NULL) ss = find_ss_for_file(nm, msg->filename);
                if (ss == NULL) {
                    send_error(client_fd, ERR_SS_UNAVAILABLE, header.seq_num);
                    break;
                }

                MessageHeader req = { .type = MSG_SS_CREATE_CHECKPOINT, .length = sizeof(CheckpointMsg), .seq_num = 0 };
                MessageHeader ss_resp;
                log_message("NM", "Sending CREATE_CHECKPOINT to SS %s:%d", ss->ip, ss->client_port);
                pthread_mutex_lock(&ss->socket_mutex);
                if (send_with_retry(ss->sockfd, &req, sizeof(MessageHeader), MAX_RETRIES) < 0 ||
                    send_with_retry(ss->sockfd, msg, sizeof(CheckpointMsg), MAX_RETRIES) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Failed to send CREATE_CHECKPOINT to SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                if (recv_with_timeout(ss->sockfd, &ss_resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Timeout/recv error waiting for CREATE_CHECKPOINT response from SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                /* If there's a payload, receive it while holding the SS socket mutex,
                   copy it to a temporary buffer, then release the mutex and forward
                   both header and payload to the client. This avoids holding the SS
                   socket mutex while performing client I/O which can block. */
                char* payload = NULL;
                if (ss_resp.length > 0) {
                    payload = (char*)malloc(ss_resp.length);
                    if (recv_with_timeout(ss->sockfd, payload, ss_resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
                        free(payload);
                        pthread_mutex_unlock(&ss->socket_mutex);
                        log_error("NM", "Timeout/recv error waiting for CREATE_CHECKPOINT payload from SS %s:%d", ss->ip, ss->client_port);
                        send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                        break;
                    }
                }

                pthread_mutex_unlock(&ss->socket_mutex);

                if (send(client_fd, &ss_resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("NM", "Failed to forward CREATE_CHECKPOINT header to client (fd=%d)", client_fd);
                }
                if (payload) {
                    send(client_fd, payload, ss_resp.length, 0);
                    free(payload);
                }
                break;
            }

            case MSG_LIST_CHECKPOINTS: {
                CheckpointListReq* msg = (CheckpointListReq*)buffer;
                log_message("NM", "LIST_CHECKPOINTS request for %s by %s", msg->filename, msg->username);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                pthread_mutex_unlock(&nm->file_index_lock);

                if (meta == NULL) {
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }

                StorageServer* ss = meta->primary_ss;
                if (ss == NULL) ss = find_ss_for_file(nm, msg->filename);
                if (ss == NULL) {
                    send_error(client_fd, ERR_SS_UNAVAILABLE, header.seq_num);
                    break;
                }

                MessageHeader req = { .type = MSG_SS_LIST_CHECKPOINTS, .length = sizeof(CheckpointListReq), .seq_num = 0 };
                MessageHeader ss_resp;
                log_message("NM", "Sending LIST_CHECKPOINTS to SS %s:%d", ss->ip, ss->client_port);
                pthread_mutex_lock(&ss->socket_mutex);
                if (send_with_retry(ss->sockfd, &req, sizeof(MessageHeader), MAX_RETRIES) < 0 ||
                    send_with_retry(ss->sockfd, msg, sizeof(CheckpointListReq), MAX_RETRIES) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Failed to send LIST_CHECKPOINTS to SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                if (recv_with_timeout(ss->sockfd, &ss_resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Timeout/recv error waiting for LIST_CHECKPOINTS response from SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                char* payload = NULL;
                if (ss_resp.length > 0) {
                    payload = (char*)malloc(ss_resp.length);
                    if (recv_with_timeout(ss->sockfd, payload, ss_resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
                        free(payload);
                        pthread_mutex_unlock(&ss->socket_mutex);
                        log_error("NM", "Timeout/recv error waiting for LIST_CHECKPOINTS payload from SS %s:%d", ss->ip, ss->client_port);
                        send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                        break;
                    }
                }

                pthread_mutex_unlock(&ss->socket_mutex);

                if (send(client_fd, &ss_resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("NM", "Failed to forward LIST_CHECKPOINTS header to client (fd=%d)", client_fd);
                }
                if (payload) {
                    send(client_fd, payload, ss_resp.length, 0);
                    free(payload);
                }
                break;
            }

            case MSG_HISTORY_REQUEST: {
                HistoryReq* msg = (HistoryReq*)buffer;
                log_message("NM", "HISTORY request for %s (max=%d) by %s", msg->filename, msg->max_entries, msg->username);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                pthread_mutex_unlock(&nm->file_index_lock);

                if (meta == NULL) {
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }

                if (!check_read_access_nolock(meta, msg->username)) {
                    // require read access to view history
                    send_error(client_fd, ERR_ACCESS_DENIED, header.seq_num);
                    break;
                }

                StorageServer* ss = meta->primary_ss;
                if (ss == NULL) ss = find_ss_for_file(nm, msg->filename);
                if (ss == NULL) {
                    send_error(client_fd, ERR_SS_UNAVAILABLE, header.seq_num);
                    break;
                }

                MessageHeader req = { .type = MSG_HISTORY_REQUEST, .length = sizeof(HistoryReq), .seq_num = 0 };
                MessageHeader ss_resp;
                log_message("NM", "Sending HISTORY to SS %s:%d", ss->ip, ss->client_port);
                pthread_mutex_lock(&ss->socket_mutex);
                if (send_with_retry(ss->sockfd, &req, sizeof(MessageHeader), MAX_RETRIES) < 0 ||
                    send_with_retry(ss->sockfd, msg, sizeof(HistoryReq), MAX_RETRIES) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Failed to send HISTORY to SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                if (recv_with_timeout(ss->sockfd, &ss_resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Timeout/recv error waiting for HISTORY response from SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                char* payload = NULL;
                if (ss_resp.length > 0) {
                    payload = (char*)malloc(ss_resp.length);
                    if (recv_with_timeout(ss->sockfd, payload, ss_resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
                        free(payload);
                        pthread_mutex_unlock(&ss->socket_mutex);
                        log_error("NM", "Timeout/recv error waiting for HISTORY payload from SS %s:%d", ss->ip, ss->client_port);
                        send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                        break;
                    }
                }

                pthread_mutex_unlock(&ss->socket_mutex);

                // Forward response to client, update seq_num to client's
                ss_resp.seq_num = header.seq_num;
                if (send(client_fd, &ss_resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("NM", "Failed to forward HISTORY header to client (fd=%d)", client_fd);
                }
                if (payload) {
                    send(client_fd, payload, ss_resp.length, 0);
                    free(payload);
                }
                break;
            }

            case MSG_VIEW_CHECKPOINT: {
                CheckpointMsg* msg = (CheckpointMsg*)buffer;
                log_message("NM", "VIEW_CHECKPOINT request for %s tag=%s by %s", msg->filename, msg->tag, msg->username);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                pthread_mutex_unlock(&nm->file_index_lock);

                if (meta == NULL) {
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }

                StorageServer* ss = meta->primary_ss;
                if (ss == NULL) ss = find_ss_for_file(nm, msg->filename);
                if (ss == NULL) {
                    send_error(client_fd, ERR_SS_UNAVAILABLE, header.seq_num);
                    break;
                }

                MessageHeader req = { .type = MSG_SS_VIEW_CHECKPOINT, .length = sizeof(CheckpointMsg), .seq_num = 0 };
                MessageHeader ss_resp;
                log_message("NM", "Sending VIEW_CHECKPOINT to SS %s:%d", ss->ip, ss->client_port);
                pthread_mutex_lock(&ss->socket_mutex);
                if (send_with_retry(ss->sockfd, &req, sizeof(MessageHeader), MAX_RETRIES) < 0 ||
                    send_with_retry(ss->sockfd, msg, sizeof(CheckpointMsg), MAX_RETRIES) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Failed to send VIEW_CHECKPOINT to SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                if (recv_with_timeout(ss->sockfd, &ss_resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Timeout/recv error waiting for VIEW_CHECKPOINT response from SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                char* payload = NULL;
                if (ss_resp.length > 0) {
                    payload = (char*)malloc(ss_resp.length);
                    if (recv_with_timeout(ss->sockfd, payload, ss_resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
                        free(payload);
                        pthread_mutex_unlock(&ss->socket_mutex);
                        log_error("NM", "Timeout/recv error waiting for VIEW_CHECKPOINT payload from SS %s:%d", ss->ip, ss->client_port);
                        send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                        break;
                    }
                }

                pthread_mutex_unlock(&ss->socket_mutex);

                if (send(client_fd, &ss_resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("NM", "Failed to forward VIEW_CHECKPOINT header to client (fd=%d)", client_fd);
                }
                if (payload) {
                    send(client_fd, payload, ss_resp.length, 0);
                    free(payload);
                }
                break;
            }

            case MSG_REVERT_CHECKPOINT: {
                CheckpointMsg* msg = (CheckpointMsg*)buffer;
                log_message("NM", "REVERT_CHECKPOINT request for %s tag=%s by %s", msg->filename, msg->tag, msg->username);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                pthread_mutex_unlock(&nm->file_index_lock);

                if (meta == NULL) {
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }

                if (!check_write_access_nolock(meta, msg->username) && strcmp(meta->owner, msg->username) != 0) {
                    send_error(client_fd, ERR_ACCESS_DENIED, header.seq_num);
                    break;
                }

                StorageServer* ss = meta->primary_ss;
                if (ss == NULL) ss = find_ss_for_file(nm, msg->filename);
                if (ss == NULL) {
                    send_error(client_fd, ERR_SS_UNAVAILABLE, header.seq_num);
                    break;
                }

                MessageHeader req = { .type = MSG_SS_REVERT_CHECKPOINT, .length = sizeof(CheckpointMsg), .seq_num = 0 };
                MessageHeader ss_resp;
                log_message("NM", "Sending REVERT_CHECKPOINT to SS %s:%d", ss->ip, ss->client_port);
                pthread_mutex_lock(&ss->socket_mutex);
                if (send_with_retry(ss->sockfd, &req, sizeof(MessageHeader), MAX_RETRIES) < 0 ||
                    send_with_retry(ss->sockfd, msg, sizeof(CheckpointMsg), MAX_RETRIES) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Failed to send REVERT_CHECKPOINT to SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                if (recv_with_timeout(ss->sockfd, &ss_resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
                    pthread_mutex_unlock(&ss->socket_mutex);
                    log_error("NM", "Timeout/recv error waiting for REVERT_CHECKPOINT response from SS %s:%d", ss->ip, ss->client_port);
                    send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                    break;
                }

                char* payload = NULL;
                if (ss_resp.length > 0) {
                    payload = (char*)malloc(ss_resp.length);
                    if (recv_with_timeout(ss->sockfd, payload, ss_resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
                        free(payload);
                        pthread_mutex_unlock(&ss->socket_mutex);
                        log_error("NM", "Timeout/recv error waiting for REVERT_CHECKPOINT payload from SS %s:%d", ss->ip, ss->client_port);
                        send_error(client_fd, ERR_NETWORK_ERROR, header.seq_num);
                        break;
                    }
                }

                pthread_mutex_unlock(&ss->socket_mutex);

                if (send(client_fd, &ss_resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("NM", "Failed to forward REVERT_CHECKPOINT header to client (fd=%d)", client_fd);
                }
                if (payload) {
                    send(client_fd, payload, ss_resp.length, 0);
                    free(payload);
                }
                break;
            }

            
            case MSG_MOVE_FILE: {
                MoveFileMsg* msg = (MoveFileMsg*)buffer;
                log_message("NM", "MOVE_FILE request %s -> %s by %s (fd=%d)", msg->src, msg->dst, msg->username, client_fd);

                // Permission: must be owner or have write access to source
                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* src_meta = search_file_cached(nm, msg->src);
                if (src_meta == NULL) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }
                if (!check_write_access_nolock(src_meta, msg->username) && strcmp(src_meta->owner, msg->username) != 0) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_ACCESS_DENIED, header.seq_num);
                    break;
                }

                // Resolve destination: if dst is a folder, move into it
                char final_dst[MAX_PATH];
                FileMetadata* dst_meta = search_file_cached(nm, msg->dst);
                if (dst_meta != NULL && dst_meta->is_folder) {
                    const char* src_basename = strrchr(msg->src, '/');
                    if (src_basename) src_basename++; else src_basename = msg->src;
                    snprintf(final_dst, MAX_PATH, "%s/%s", msg->dst, src_basename);
                } else {
                    strncpy(final_dst, msg->dst, MAX_PATH - 1);
                    final_dst[MAX_PATH - 1] = '\0';
                }

                bool moved = move_file((TrieNode*)nm->file_index, msg->src, final_dst);
                if (moved) {
                    // update cache
                    cache_invalidate(nm->search_cache, msg->src);
                    FileMetadata* newmeta = search_file_cached(nm, final_dst);
                    if (newmeta) cache_put(nm->search_cache, final_dst, newmeta);
                }
                pthread_mutex_unlock(&nm->file_index_lock);

                if (moved) {
                    MessageHeader resp;
                    resp.type = MSG_SUCCESS;
                    resp.length = 0;
                    resp.seq_num = header.seq_num;
                    send(client_fd, &resp, sizeof(MessageHeader), 0);
                } else {
                    // Try to determine failure reason
                    FileMetadata* conflict = search_file((TrieNode*)nm->file_index, final_dst);
                    if (conflict != NULL) {
                        send_error(client_fd, ERR_FILE_EXISTS, header.seq_num);
                    } else {
                        // If source no longer exists, it's a not-found; otherwise generic internal error
                        FileMetadata* still_src = search_file((TrieNode*)nm->file_index, msg->src);
                        if (still_src == NULL) {
                            send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                        } else {
                            send_error(client_fd, ERR_INTERNAL, header.seq_num);
                        }
                    }
                }

                if (moved) {
                    // Inform SSs to move on disk (best-effort)
                    pthread_mutex_lock(&nm->ss_lock);
                    int ss_count = 0;
                    for (StorageServer* s = nm->ss_list; s != NULL; s = s->next) if (s->active) ss_count++;
                    StorageServer** ss_arr = NULL;
                    if (ss_count > 0) {
                        ss_arr = (StorageServer**)malloc(ss_count * sizeof(StorageServer*));
                        int idx = 0;
                        for (StorageServer* s = nm->ss_list; s != NULL; s = s->next) {
                            if (!s->active) continue;
                            ss_arr[idx++] = s;
                        }
                    }
                    pthread_mutex_unlock(&nm->ss_lock);

                    if (ss_arr) {
                        MoveFileMsg mvmsg;
                        strncpy(mvmsg.src, msg->src, MAX_PATH - 1);
                        mvmsg.src[MAX_PATH - 1] = '\0';
                        strncpy(mvmsg.dst, final_dst, MAX_PATH - 1);
                        mvmsg.dst[MAX_PATH - 1] = '\0';
                        strncpy(mvmsg.username, msg->username, MAX_USERNAME - 1);
                        mvmsg.username[MAX_USERNAME - 1] = '\0';

                        MessageHeader req = { .type = MSG_SS_MOVE_FILE, .length = sizeof(MoveFileMsg), .seq_num = 0 };
                        for (int i = 0; i < ss_count; i++) {
                            StorageServer* s = ss_arr[i];
                            pthread_mutex_lock(&s->socket_mutex);
                            if (send(s->sockfd, &req, sizeof(MessageHeader), 0) == sizeof(MessageHeader)) {
                                send(s->sockfd, &mvmsg, sizeof(MoveFileMsg), 0);
                            } else {
                                log_error("NM", "Failed to notify SS %s:%d about file move", s->ip, s->client_port);
                            }
                            pthread_mutex_unlock(&s->socket_mutex);
                        }
                        free(ss_arr);
                    }
                }
                break;
            }
            
            case MSG_READ_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("NM", "READ request for %s by %s (fd=%d)", msg->filename, msg->username, client_fd);
                
                // Lookup and permission check (protected region)
                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                if (meta == NULL) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    log_error("NM", "File %s not found", msg->filename);
                    break;
                }

                if (!check_read_access_nolock(meta, msg->username)) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_ACCESS_DENIED, header.seq_num);
                    log_error("NM", "User %s has no read access to %s", msg->username, msg->filename);
                    break;
                }

                // Update access time and grab SS pointer then release lock
                update_file_access_time(meta);
                StorageServer* ss = meta->primary_ss; // read under lock
                pthread_mutex_unlock(&nm->file_index_lock);
                if (ss == NULL) {
                    ss = find_ss_for_file(nm, msg->filename);
                }
                if (ss != NULL) {
                    RedirectMsg redirect;
                    strncpy(redirect.ss_ip, ss->ip, MAX_IP - 1);
                    redirect.ss_ip[MAX_IP - 1] = '\0';
                    redirect.ss_port = ss->client_port;
                    
                    MessageHeader resp_header;
                    resp_header.type = MSG_REDIRECT;
                    resp_header.length = sizeof(RedirectMsg);
                    resp_header.seq_num = header.seq_num;
                    
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    send(client_fd, &redirect, sizeof(RedirectMsg), 0);
                    log_message("NM", "Redirected READ to SS %s:%d (fd=%d)", ss->ip, ss->client_port, client_fd);
                } else {
                    send_error(client_fd, ERR_SS_UNAVAILABLE, header.seq_num);
                    log_error("NM", "No storage server found for %s", msg->filename);
                }
                break;
            }
            
            case MSG_DELETE_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                handle_delete_file(nm, client_fd, msg);
                break;
            }
            
            case MSG_INFO_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                handle_file_info(nm, client_fd, msg);
                break;
            }
            
            case MSG_WRITE_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("NM", "WRITE request for %s by %s (fd=%d)", msg->filename, msg->username, client_fd);
                
                // Lookup and permission check (protected region)
                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                if (meta == NULL) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    log_error("NM", "File %s not found", msg->filename);
                    break;
                }

                if (!check_write_access_nolock(meta, msg->username)) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_ACCESS_DENIED, header.seq_num);
                    log_error("NM", "User %s has no write access to %s", msg->username, msg->filename);
                    break;
                }

                StorageServer* ss = meta->primary_ss; // read under lock
                pthread_mutex_unlock(&nm->file_index_lock);
                if (ss == NULL) {
                    ss = find_ss_for_file(nm, msg->filename);
                }
                if (ss != NULL) {
                    RedirectMsg redirect;
                    strncpy(redirect.ss_ip, ss->ip, MAX_IP - 1);
                    redirect.ss_ip[MAX_IP - 1] = '\0';
                    redirect.ss_port = ss->client_port;
                    
                    MessageHeader resp_header;
                    resp_header.type = MSG_REDIRECT;
                    resp_header.length = sizeof(RedirectMsg);
                    resp_header.seq_num = header.seq_num;
                    
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    send(client_fd, &redirect, sizeof(RedirectMsg), 0);
                    log_message("NM", "Redirected WRITE to SS %s:%d (fd=%d)", ss->ip, ss->client_port, client_fd);
                } else {
                    MessageHeader resp_header;
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    log_error("NM", "No storage server found for %s", msg->filename);
                }
                break;
            }
            
            case MSG_STREAM_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("NM", "STREAM request for %s by %s (fd=%d)", msg->filename, msg->username, client_fd);
                
                // Lookup and permission check (protected region)
                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                if (meta == NULL) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    log_error("NM", "File %s not found", msg->filename);
                    break;
                }

                if (!check_read_access(meta, msg->username)) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_ACCESS_DENIED, header.seq_num);
                    log_error("NM", "User %s has no read access to %s", msg->username, msg->filename);
                    break;
                }

                StorageServer* ss = meta->primary_ss; // read under lock
                pthread_mutex_unlock(&nm->file_index_lock);
                if (ss == NULL) {
                    ss = find_ss_for_file(nm, msg->filename);
                }
                if (ss != NULL) {
                    RedirectMsg redirect;
                    strncpy(redirect.ss_ip, ss->ip, MAX_IP - 1);
                    redirect.ss_ip[MAX_IP - 1] = '\0';
                    redirect.ss_port = ss->client_port;
                    
                    MessageHeader resp_header;
                    resp_header.type = MSG_REDIRECT;
                    resp_header.length = sizeof(RedirectMsg);
                    resp_header.seq_num = header.seq_num;
                    
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    send(client_fd, &redirect, sizeof(RedirectMsg), 0);
                    log_message("NM", "Redirected STREAM to SS %s:%d (fd=%d)", ss->ip, ss->client_port, client_fd);
                } else {
                    MessageHeader resp_header;
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    log_error("NM", "No storage server found for %s", msg->filename);
                }
                break;
            }
            
            case MSG_UNDO_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("NM", "UNDO request for %s by %s (fd=%d)", msg->filename, msg->username, client_fd);
                
                // Lookup and permission check (protected region)
                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                if (meta == NULL) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    MessageHeader resp_header;
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    log_error("NM", "File %s not found", msg->filename);
                    break;
                }

                if (!check_write_access_nolock(meta, msg->username)) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    MessageHeader resp_header;
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    log_error("NM", "User %s has no write access to %s", msg->username, msg->filename);
                    break;
                }

                StorageServer* ss = meta->primary_ss; // read under lock
                pthread_mutex_unlock(&nm->file_index_lock);
                if (ss == NULL) {
                    ss = find_ss_for_file(nm, msg->filename);
                }
                if (ss != NULL) {
                    RedirectMsg redirect;
                    strncpy(redirect.ss_ip, ss->ip, MAX_IP - 1);
                    redirect.ss_ip[MAX_IP - 1] = '\0';
                    redirect.ss_port = ss->client_port;
                    
                    MessageHeader resp_header;
                    resp_header.type = MSG_REDIRECT;
                    resp_header.length = sizeof(RedirectMsg);
                    resp_header.seq_num = header.seq_num;
                    
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    send(client_fd, &redirect, sizeof(RedirectMsg), 0);
                    log_message("NM", "Redirected UNDO to SS %s:%d (fd=%d)", ss->ip, ss->client_port, client_fd);
                } else {
                    MessageHeader resp_header;
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
                    log_error("NM", "No storage server found for %s", msg->filename);
                }
                break;
            }
            
            case MSG_LIST_USERS: {
                handle_list_users(nm, client_fd);
                break;
            }
            
            case MSG_ADD_ACCESS: {
                AccessMsg* msg = (AccessMsg*)buffer;
                handle_access_control(nm, client_fd, msg);
                break;
            }

            case MSG_REQUEST_ACCESS: {
                RequestAccessMsg* msg = (RequestAccessMsg*)buffer;
                log_message("NM", "REQUEST_ACCESS for %s by %s (fd=%d)", msg->filename, msg->username, client_fd);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                if (meta == NULL) {
                    pthread_mutex_unlock(&nm->file_index_lock);
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }
                // Add request under metadata lock (do not hold file_index_lock while calling into meta helpers)
                pthread_mutex_unlock(&nm->file_index_lock);

                add_access_request(meta, msg->username);

                MessageHeader resp;
                resp.type = MSG_SUCCESS;
                resp.length = 0;
                resp.seq_num = header.seq_num;
                send(client_fd, &resp, sizeof(MessageHeader), 0);
                break;
            }

            case MSG_LIST_ACCESS_REQUESTS: {
                AccessListReq* msg = (AccessListReq*)buffer;
                log_message("NM", "LIST_ACCESS_REQUESTS for %s by %s (fd=%d)", msg->filename, msg->username, client_fd);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                pthread_mutex_unlock(&nm->file_index_lock);

                if (meta == NULL) {
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }
                // Only owner can list requests
                if (strcmp(meta->owner, msg->username) != 0) {
                    send_error(client_fd, ERR_ACCESS_DENIED, header.seq_num);
                    break;
                }

                // Build response: newline-separated requester names
                char listbuf[1024];
                list_access_requests_string(meta, listbuf, sizeof(listbuf));

                MessageHeader resp;
                resp.type = MSG_SUCCESS;
                resp.length = strlen(listbuf) + 1;
                resp.seq_num = header.seq_num;
                send(client_fd, &resp, sizeof(MessageHeader), 0);
                if (resp.length > 0) send(client_fd, listbuf, resp.length, 0);
                break;
            }

            case MSG_RESPOND_ACCESS_REQUEST: {
                AccessResponseMsg* msg = (AccessResponseMsg*)buffer;
                log_message("NM", "RESPOND_ACCESS for %s target=%s by %s approve=%d grant_write=%d (fd=%d)",
                            msg->filename, msg->target_user, msg->username, msg->approve, msg->grant_write, client_fd);

                pthread_mutex_lock(&nm->file_index_lock);
                FileMetadata* meta = search_file_cached(nm, msg->filename);
                pthread_mutex_unlock(&nm->file_index_lock);

                if (meta == NULL) {
                    send_error(client_fd, ERR_FILE_NOT_FOUND, header.seq_num);
                    break;
                }

                // Only owner may approve/deny
                if (strcmp(meta->owner, msg->username) != 0) {
                    send_error(client_fd, ERR_NOT_OWNER, header.seq_num);
                    break;
                }

                // If approving, modify ACLs under file_index_lock (to mirror other access control flows)
                StorageServer* target_ss = NULL;
                SSMetadataTransferMsg transfer_msg;
                memset(&transfer_msg, 0, sizeof(transfer_msg));

                pthread_mutex_lock(&nm->file_index_lock);
                if (msg->approve) {
                    if (msg->grant_write) add_write_access(meta, msg->target_user);
                    else add_read_access(meta, msg->target_user);
                }
                target_ss = meta->primary_ss;
                strncpy(transfer_msg.filename, meta->filename, MAX_FILENAME - 1);
                strncpy(transfer_msg.owner, meta->owner, MAX_USERNAME - 1);
                transfer_msg.created = meta->created;
                transfer_msg.last_modified = meta->last_modified;
                transfer_msg.last_accessed = meta->last_accessed;
                transfer_msg.size = meta->size;
                transfer_msg.word_count = meta->word_count;
                transfer_msg.char_count = meta->char_count;

                transfer_msg.read_users[0] = '\0';
                transfer_msg.write_users[0] = '\0';
                for (int i = 0; i < meta->num_read_users; i++) {
                    if (strlen(transfer_msg.read_users) + strlen(meta->read_users[i]) + 2 < MAX_ACL_STRING) {
                        if (transfer_msg.read_users[0] != '\0') strncat(transfer_msg.read_users, ",", MAX_ACL_STRING - strlen(transfer_msg.read_users) - 1);
                        strncat(transfer_msg.read_users, meta->read_users[i], MAX_ACL_STRING - strlen(transfer_msg.read_users) - 1);
                    }
                }
                for (int i = 0; i < meta->num_write_users; i++) {
                    if (strlen(transfer_msg.write_users) + strlen(meta->write_users[i]) + 2 < MAX_ACL_STRING) {
                        if (transfer_msg.write_users[0] != '\0') strncat(transfer_msg.write_users, ",", MAX_ACL_STRING - strlen(transfer_msg.write_users) - 1);
                        strncat(transfer_msg.write_users, meta->write_users[i], MAX_ACL_STRING - strlen(transfer_msg.write_users) - 1);
                    }
                }

                pthread_mutex_unlock(&nm->file_index_lock);

                // Remove the pending request entry regardless of approve/deny
                remove_access_request(meta, msg->target_user);

                MessageHeader resp;
                resp.type = MSG_SUCCESS;
                resp.length = 0;
                resp.seq_num = header.seq_num;
                send(client_fd, &resp, sizeof(MessageHeader), 0);

                // Push metadata update to storage server if present
                if (target_ss != NULL) {
                    MessageHeader nm_to_ss;
                    nm_to_ss.type = MSG_SS_UPDATE_METADATA;
                    nm_to_ss.length = sizeof(SSMetadataTransferMsg);
                    nm_to_ss.seq_num = 0;

                    pthread_mutex_lock(&target_ss->socket_mutex);
                    if (send(target_ss->sockfd, &nm_to_ss, sizeof(MessageHeader), 0) == sizeof(MessageHeader) &&
                        send(target_ss->sockfd, &transfer_msg, sizeof(SSMetadataTransferMsg), 0) == sizeof(SSMetadataTransferMsg)) {
                        MessageHeader ss_resp;
                        if (recv(target_ss->sockfd, &ss_resp, sizeof(MessageHeader), MSG_WAITALL) == sizeof(MessageHeader)) {
                            if (ss_resp.type == MSG_SUCCESS) {
                                log_message("NM", "Pushed ACL update for %s to SS %s:%d", transfer_msg.filename, target_ss->ip, target_ss->client_port);
                            } else {
                                log_error("NM", "SS rejected ACL update for %s", transfer_msg.filename);
                            }
                        } else {
                            log_error("NM", "No ACK from SS when pushing ACL update for %s", transfer_msg.filename);
                        }
                    } else {
                        log_error("NM", "Failed to send ACL update to SS for %s", transfer_msg.filename);
                    }
                    pthread_mutex_unlock(&target_ss->socket_mutex);
                }

                break;
            }
            
            case MSG_REM_ACCESS: {
                AccessMsg* msg = (AccessMsg*)buffer;
                // For REMACCESS, we set both read and write to false
                msg->read_access = false;
                msg->write_access = false;
                handle_access_control(nm, client_fd, msg);
                break;
            }
            
            case MSG_EXEC_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                handle_exec(nm, client_fd, msg);
                break;
            }
            
            default:
                log_error("NM", "Unknown message type: %d (fd=%d)", header.type, client_fd);
                break;
        }
    }
    
    close(client_fd);
    return NULL;
}

// Handle CREATE file request
void handle_create_file(NameServer* nm, int client_fd, FileOpMsg* msg) {
    log_message("NM", "CREATE request for %s by %s (fd=%d)", msg->filename, msg->username, client_fd);
    
    // Check if file already exists (use cached search)
    FileMetadata* existing = search_file_cached(nm, msg->filename);
    if (existing != NULL) {
        send_error(client_fd, ERR_FILE_EXISTS, 0);
        log_error("NM", "File %s already exists", msg->filename);
        return;
    }
    
    // Choose an available SS (simple: use first active one)
    pthread_mutex_lock(&nm->ss_lock);
    StorageServer* ss = nm->ss_list;
    while (ss != NULL && !ss->active) {
        ss = ss->next;
    }
    pthread_mutex_unlock(&nm->ss_lock);
    
    if (ss == NULL) {
        send_error(client_fd, ERR_SS_UNAVAILABLE, 0);
        log_error("NM", "No storage server available");
        return;
    }
    
    log_message("NM", "Forwarding CREATE to SS (fd=%d)", ss->sockfd);
    
    // Forward to SS
    MessageHeader req_header;
    req_header.type = MSG_SS_CREATE_FILE;
    req_header.length = sizeof(FileOpMsg);
    req_header.seq_num = 0;
    
    if (send(ss->sockfd, &req_header, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
        log_error("NM", "Failed to send CREATE request to SS");
        send_error(client_fd, ERR_NETWORK_ERROR, 0);
        return;
    }
    
    if (send(ss->sockfd, msg, sizeof(FileOpMsg), 0) != sizeof(FileOpMsg)) {
        log_error("NM", "Failed to send CREATE payload to SS");
        send_error(client_fd, ERR_NETWORK_ERROR, 0);
        return;
    }
    
    // Wait for SS response (SS sends ACK to NM)
    MessageHeader ss_resp;
    ssize_t recv_result = recv(ss->sockfd, &ss_resp, sizeof(MessageHeader), MSG_WAITALL);
    if (recv_result != sizeof(MessageHeader)) {
        log_error("NM", "Failed to receive CREATE ACK from SS");
        send_error(client_fd, ERR_NETWORK_ERROR, 0);
        return;
    }
    
    log_message("NM", "Received CREATE response from SS: type=%d", ss_resp.type);
    
    // Forward response to client with proper seq_num
    MessageHeader resp_header;
    resp_header.type = ss_resp.type;
    resp_header.length = 0;
    resp_header.seq_num = 0;
    if (send(client_fd, &resp_header, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
        log_error("NM", "Failed to send CREATE response to client");
        return;
    }
    
    // Update file index and cache if successful
    if (ss_resp.type == MSG_SUCCESS) {
        FileMetadata* meta = create_file_metadata(msg->filename, msg->username);
        meta->primary_ss = ss;
        pthread_mutex_lock(&nm->file_index_lock);
        insert_file((TrieNode*)nm->file_index, msg->filename, meta);
        // cache_put uses its own lock internally
        cache_put(nm->search_cache, msg->filename, meta);  // Add to cache for quick access
        pthread_mutex_unlock(&nm->file_index_lock);
        log_message("NM", "Added %s to cache after creation", msg->filename);
        
        // Add to SS file list
        pthread_mutex_lock(&nm->ss_lock);
        ss->files = (char**)realloc(ss->files, (ss->num_files + 1) * sizeof(char*));
        ss->files[ss->num_files] = (char*)malloc(MAX_FILENAME);
        strncpy(ss->files[ss->num_files], msg->filename, MAX_FILENAME - 1);
        ss->files[ss->num_files][MAX_FILENAME - 1] = '\0';
        ss->num_files++;
        pthread_mutex_unlock(&nm->ss_lock);

        
        log_message("NM", "File %s created and added to index", msg->filename);
        // Asynchronously ensure a replica exists on another storage server
        pthread_mutex_lock(&nm->ss_lock);
        StorageServer* candidate = nm->ss_list;
        StorageServer* replica = NULL;
        while (candidate != NULL) {
            if (candidate->active && candidate != ss) {
                replica = candidate;
                break;
            }
            candidate = candidate->next;
        }
        pthread_mutex_unlock(&nm->ss_lock);

        if (replica != NULL) {
            // Assign replica pointer in metadata and instruct replica to pull file
            meta->replica_ss = replica;
            SSReplicateMsg rmsg;
            memset(&rmsg, 0, sizeof(rmsg));
            strncpy(rmsg.filename, msg->filename, MAX_FILENAME - 1);
            strncpy(rmsg.src_ip, ss->ip, MAX_IP - 1);
            rmsg.src_port = ss->client_port;

            MessageHeader rh = { .type = MSG_SS_PULL_FILE, .length = sizeof(SSReplicateMsg), .seq_num = 0 };
            pthread_mutex_lock(&replica->socket_mutex);
            if (send_with_retry(replica->sockfd, &rh, sizeof(MessageHeader), 3) == 0 &&
                send_with_retry(replica->sockfd, &rmsg, sizeof(SSReplicateMsg), 3) == 0) {
                // Optionally wait for confirmation
                MessageHeader resp;
                if (recv_with_timeout(replica->sockfd, &resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) == 0 && resp.type == MSG_SUCCESS) {
                    log_message("NM", "Replica %s:%d pulled %s successfully", replica->ip, replica->client_port, rmsg.filename);
                } else {
                    log_error("NM", "Replica %s:%d failed to pull %s or timed out", replica->ip, replica->client_port, rmsg.filename);
                }
            } else {
                log_error("NM", "Failed to send replication request to %s:%d", replica->ip, replica->client_port);
            }
            pthread_mutex_unlock(&replica->socket_mutex);
        }
    }
}

// Start Name Server
void nm_start(NameServer* nm) {
    nm->server_sockfd = create_tcp_socket();
    if (nm->server_sockfd < 0) {
        log_error("NM", "Failed to create server socket");
        return;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(nm->nm_port);
    
    if (bind(nm->server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("NM", "Failed to bind server socket");
        close(nm->server_sockfd);
        return;
    }
    
    if (listen(nm->server_sockfd, 20) < 0) {
        log_error("NM", "Failed to listen");
        close(nm->server_sockfd);
        return;
    }
    
    log_message("NM", "Name Server listening on port %d", nm->nm_port);
    // Start background threads: health check and replication manager
    pthread_t health_thread, repl_thread;
    pthread_create(&health_thread, NULL, nm_health_check_thread, nm);
    pthread_create(&repl_thread, NULL, nm_replication_thread, nm);
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int conn_fd = accept(nm->server_sockfd, (struct sockaddr*)&client_addr, &addr_len);
        if (conn_fd < 0) {
            log_error("NM", "Failed to accept connection");
            continue;
        }
        
        log_message("NM", "New connection from %s:%d (fd=%d)", 
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), conn_fd);
        
        
        // Peek at first message to determine if it's SS or Client
        MessageHeader peek_header;
        if (recv(conn_fd, &peek_header, sizeof(MessageHeader), MSG_PEEK) == sizeof(MessageHeader)) {
            if (peek_header.type == MSG_SS_REGISTER) {
                // Handle SS registration in main thread
                recv(conn_fd, &peek_header, sizeof(MessageHeader), MSG_WAITALL);
                
                SSRegisterMsg reg_msg;
                recv(conn_fd, &reg_msg, sizeof(SSRegisterMsg), MSG_WAITALL);
                
                register_storage_server(nm, &reg_msg, conn_fd);
                
                // Receive file list
                pthread_mutex_lock(&nm->ss_lock);
                StorageServer* ss = nm->ss_list;  // Just registered, at head

int ss_sockfd = ss->sockfd;  // Copy socket fd
pthread_mutex_unlock(&nm->ss_lock);  // RELEASE LOCK BEFORE I/O
                  for (int i = 0; i < reg_msg.num_files; i++) {
                    recv(conn_fd, ss->files[i], MAX_FILENAME, MSG_WAITALL);
                    log_message("NM", "  - SS reported file: %s", ss->files[i]);
                    
                    FileMetadata* existing = search_file((TrieNode*)nm->file_index, ss->files[i]);
                    if (existing == NULL) {
                        log_message("NM", "File %s not in index. Querying SS for metadata.", ss->files[i]);

                        MessageHeader req_header = { .type = MSG_SS_GET_METADATA, .length = sizeof(FileOpMsg) };
                        FileOpMsg file_msg;
                        strncpy(file_msg.filename, ss->files[i], MAX_FILENAME - 1);
                        
                        send(ss->sockfd, &req_header, sizeof(MessageHeader), 0);
                        send(ss->sockfd, &file_msg, sizeof(FileOpMsg), 0);
                        
                        MessageHeader meta_resp_header;
                        if (recv(ss->sockfd, &meta_resp_header, sizeof(MessageHeader), MSG_WAITALL) == sizeof(MessageHeader) && meta_resp_header.type == MSG_SUCCESS) {
                            
                            SSMetadataTransferMsg transfer_msg;
                            recv(ss->sockfd, &transfer_msg, sizeof(SSMetadataTransferMsg), MSG_WAITALL);

                            FileMetadata* meta = create_file_metadata(transfer_msg.filename, transfer_msg.owner);
                            meta->primary_ss = ss;
                            meta->created = transfer_msg.created;
                            meta->last_modified = transfer_msg.last_modified;
                            meta->last_accessed = transfer_msg.last_accessed;
                            meta->word_count = transfer_msg.word_count;
                            meta->char_count = transfer_msg.char_count;
                            
                            // Rebuild access lists from comma-separated strings
                            char* saveptr;
                            char* token = strtok_r(transfer_msg.read_users, ",", &saveptr);
                            while (token != NULL) {
                                add_read_access(meta, token);
                                token = strtok_r(NULL, ",", &saveptr);
                            }
                            
                            token = strtok_r(transfer_msg.write_users, ",", &saveptr);
                            while (token != NULL) {
                                add_write_access(meta, token);
                                token = strtok_r(NULL, ",", &saveptr);
                            }
                            
                            pthread_mutex_lock(&nm->file_index_lock);
                            insert_file((TrieNode*)nm->file_index, meta->filename, meta);
                            pthread_mutex_unlock(&nm->file_index_lock);
                            log_message("NM", "    Successfully restored metadata for %s from SS. Owner: %s", meta->filename, meta->owner);
                        } else {
                            log_error("NM", "    Failed to get metadata for %s from SS. Skipping.", ss->files[i]);
                        }
                    } else {
                        existing->primary_ss = ss;
                        log_message("NM", "    Restored SS reference for existing metadata for %s", ss->files[i]);
                    }
                    // ===================== MODIFICATION END =====================
                }
                
                // Send ACK
                MessageHeader ack;
                ack.type = MSG_SUCCESS;
                ack.length = 0;
                ack.seq_num = 0;
                send(conn_fd, &ack, sizeof(MessageHeader), 0);
                
                log_message("NM", "SS registration complete");
                
                // Start thread to handle SS requests
                pthread_t ss_thread;
                ThreadArg* ss_arg = malloc(sizeof(ThreadArg));
                ss_arg->nm = nm;
                ss_arg->sockfd = conn_fd;
                pthread_create(&ss_thread, NULL, handle_ss_connection, ss_arg);
                pthread_detach(ss_thread);
            } else {
                // Handle client connection
                pthread_t client_thread;
                ThreadArg* client_arg = malloc(sizeof(ThreadArg));
                client_arg->nm = nm;
                client_arg->sockfd = conn_fd;
                pthread_create(&client_thread, NULL, handle_client_connection, client_arg);
                pthread_detach(client_thread);
            }
        }
    }
}

// Handle SS connection (keep-alive)
void* handle_ss_connection(void* arg) {
    ThreadArg* targ = (ThreadArg*)arg;
    int ss_fd = targ->sockfd;
    NameServer* nm = targ->nm;
    free(targ);
    
    log_message("NM", "SS connection handler started (fd=%d)", ss_fd);
    
    // DISABLED: Do not continuously read from SS socket here
    // This was causing race conditions with handle_create_file/handle_delete_file/handle_exec
    // which also try to recv() from the same socket.
    // 
    // The SS connection is kept alive, but NM initiates all communication via
    // request-response pattern in the respective handler functions.
    // 
    // TODO: If we need to detect SS disconnections, use a heartbeat/ping mechanism
    // or check for errors when sending requests.
    
    log_message("NM", "SS connection handler exiting immediately (no continuous read) (fd=%d)", ss_fd);
    return NULL;
}

// Background health-check thread: ping SSs and promote replicas when needed
void* nm_health_check_thread(void* arg) {
    NameServer* nm = (NameServer*)arg;
    const int HEALTH_INTERVAL = 5; // seconds
    while (1) {
        sleep(HEALTH_INTERVAL);
        pthread_mutex_lock(&nm->ss_lock);
        StorageServer* s = nm->ss_list;
        while (s != NULL) {
            pthread_mutex_lock(&s->socket_mutex);
            MessageHeader ping = { .type = MSG_PING, .length = 0, .seq_num = 0 };
            if (send_with_retry(s->sockfd, &ping, sizeof(MessageHeader), 1) < 0) {
                log_error("NM", "Health check: failed to send ping to SS %s:%d", s->ip, s->client_port);
                s->active = false;
                pthread_mutex_unlock(&s->socket_mutex);
                s = s->next;
                continue;
            }
            MessageHeader resp;
            if (recv_with_timeout(s->sockfd, &resp, sizeof(MessageHeader), 2) < 0 || resp.type != MSG_PONG) {
                log_error("NM", "Health check: no pong from SS %s:%d - marking inactive", s->ip, s->client_port);
                s->active = false;
                pthread_mutex_unlock(&s->socket_mutex);
                s = s->next;
                continue;
            }
            s->last_heartbeat = time(NULL);
            pthread_mutex_unlock(&s->socket_mutex);
            s = s->next;
        }
        pthread_mutex_unlock(&nm->ss_lock);

        // Promote replicas for any files whose primary is inactive
        pthread_mutex_lock(&nm->file_index_lock);
        FileMetadata** all_files = NULL;
        int count = 0;
        collect_all_files((TrieNode*)nm->file_index, &all_files, &count, "");
        for (int i = 0; i < count; i++) {
            FileMetadata* m = all_files[i];
            if (m->primary_ss != NULL && !m->primary_ss->active) {
                if (m->replica_ss != NULL && m->replica_ss->active) {
                    log_message("NM", "Promoting replica for %s to primary", m->filename);
                    m->primary_ss = m->replica_ss;
                    m->replica_ss = NULL; // replication manager will fix backups
                } else {
                    log_error("NM", "No available replica to promote for %s", m->filename);
                }
            }
        }
        free(all_files);
        pthread_mutex_unlock(&nm->file_index_lock);
    }
    return NULL;
}

// Background replication manager: ensure every file has a replica
void* nm_replication_thread(void* arg) {
    NameServer* nm = (NameServer*)arg;
    const int REP_INTERVAL = 6; // seconds
    while (1) {
        sleep(REP_INTERVAL);
        pthread_mutex_lock(&nm->file_index_lock);
        FileMetadata** all_files = NULL;
        int count = 0;
        collect_all_files((TrieNode*)nm->file_index, &all_files, &count, "");
        for (int i = 0; i < count; i++) {
            FileMetadata* m = all_files[i];
            if (m->primary_ss == NULL || !m->primary_ss->active) continue;
            if (m->replica_ss == NULL || !m->replica_ss->active) {
                pthread_mutex_lock(&nm->ss_lock);
                StorageServer* cand = nm->ss_list;
                StorageServer* chosen = NULL;
                while (cand != NULL) {
                    if (cand->active && cand != m->primary_ss) { chosen = cand; break; }
                    cand = cand->next;
                }
                pthread_mutex_unlock(&nm->ss_lock);

                if (chosen != NULL) {
                    m->replica_ss = chosen;
                    SSReplicateMsg rmsg;
                    memset(&rmsg, 0, sizeof(rmsg));
                    strncpy(rmsg.filename, m->filename, MAX_FILENAME - 1);
                    strncpy(rmsg.src_ip, m->primary_ss->ip, MAX_IP - 1);
                    rmsg.src_port = m->primary_ss->client_port;

                    MessageHeader rh = { .type = MSG_SS_PULL_FILE, .length = sizeof(SSReplicateMsg), .seq_num = 0 };
                    pthread_mutex_lock(&chosen->socket_mutex);
                    if (send_with_retry(chosen->sockfd, &rh, sizeof(MessageHeader), 3) == 0 &&
                        send_with_retry(chosen->sockfd, &rmsg, sizeof(SSReplicateMsg), 3) == 0) {
                        MessageHeader resp;
                        if (recv_with_timeout(chosen->sockfd, &resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) == 0 && resp.type == MSG_SUCCESS) {
                            log_message("NM", "Replication: %s copied to %s:%d", m->filename, chosen->ip, chosen->client_port);
                        } else {
                            log_error("NM", "Replication: %s failed on %s:%d", m->filename, chosen->ip, chosen->client_port);
                            m->replica_ss = NULL;
                        }
                    } else {
                        log_error("NM", "Failed to send replication request for %s to %s:%d", m->filename, chosen->ip, chosen->client_port);
                        m->replica_ss = NULL;
                    }
                    pthread_mutex_unlock(&chosen->socket_mutex);
                }
            }
        }
        free(all_files);
        pthread_mutex_unlock(&nm->file_index_lock);
    }
    return NULL;
}

// Handle VIEW files request
void handle_view_files(NameServer* nm, int client_fd, ViewMsg* msg) {
    log_message("NM", "VIEW request by %s (all=%d, details=%d)", 
                msg->username, msg->show_all, msg->show_details);

    // Collect all files from Trie (protected by file_index_lock)
    pthread_mutex_lock(&nm->file_index_lock);
    FileMetadata** all_files = NULL;
    int total_count = 0;
    collect_all_files((TrieNode*)nm->file_index, &all_files, &total_count, "");
    
    // Filter by access if not show_all
    FileInfo* file_list = (FileInfo*)malloc(total_count * sizeof(FileInfo));
    int accessible_count = 0;
    
    for (int i = 0; i < total_count; i++) {
        FileMetadata* meta = all_files[i];

        // Check access (skip if not show_all and no access)
    if (!msg->show_all && !check_read_access_nolock(meta, msg->username)) {
            continue;
        }

        // Add to result (copy fields while holding lock)
        FileInfo* info = &file_list[accessible_count];
        strncpy(info->filename, meta->filename, MAX_FILENAME - 1);
        info->filename[MAX_FILENAME - 1] = '\0';
        strncpy(info->owner, meta->owner, MAX_USERNAME - 1);
        info->owner[MAX_USERNAME - 1] = '\0';
        info->word_count = meta->word_count;
        info->char_count = meta->char_count;

        // Format timestamps
        strftime(info->last_access, sizeof(info->last_access), 
                "%Y-%m-%d %H:%M", localtime(&meta->last_accessed));
        strftime(info->created, sizeof(info->created), 
                "%Y-%m-%d %H:%M", localtime(&meta->created));

        accessible_count++;
    }

    pthread_mutex_unlock(&nm->file_index_lock);
    
    // Send response
    MessageHeader resp_header;
    resp_header.type = MSG_SUCCESS;
    resp_header.length = accessible_count * sizeof(FileInfo);
    resp_header.seq_num = 0;
    
    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
    if (accessible_count > 0) {
        send(client_fd, file_list, resp_header.length, 0);
    }
    
    log_message("NM", "Sent %d files to client", accessible_count);
    
    // Cleanup
    free(all_files);
    free(file_list);
}

void handle_delete_file(NameServer* nm, int client_fd, FileOpMsg* msg) {
    log_message("NM", "DELETE request for %s by %s", msg->filename, msg->username);
    
    // Check if file exists (use cached search)
    FileMetadata* meta = search_file_cached(nm, msg->filename);
    if (meta == NULL) {
        send_error(client_fd, ERR_FILE_NOT_FOUND, 0);
        return;
    }
    
    // Check if user is owner
    if (strcmp(meta->owner, msg->username) != 0) {
        send_error(client_fd, ERR_NOT_OWNER, 0);
        return;
    }
    
    // Find storage server
    StorageServer* ss = find_ss_for_file(nm, msg->filename);
    if (ss == NULL) {
        send_error(client_fd, ERR_SS_UNAVAILABLE, 0);
        return;
    }
    
    // Forward delete request to storage server
    MessageHeader req_header;
    req_header.type = MSG_SS_DELETE_FILE;
    req_header.length = sizeof(FileOpMsg);
    req_header.seq_num = 0;
    
    send(ss->sockfd, &req_header, sizeof(MessageHeader), 0);
    send(ss->sockfd, msg, sizeof(FileOpMsg), 0);
    
    // Wait for SS response
    MessageHeader ss_resp;
    ssize_t recv_result = recv(ss->sockfd, &ss_resp, sizeof(MessageHeader), MSG_WAITALL);
    if (recv_result != sizeof(MessageHeader)) {
        send_error(client_fd, ERR_NETWORK_ERROR, 0);
        log_error("NM", "Failed to receive DELETE response from SS for %s", msg->filename);
        return;
    }
    
    // Forward response to client
    send(client_fd, &ss_resp, sizeof(MessageHeader), 0);
    
    // If successful, remove from file index and cache
    if (ss_resp.type == MSG_SUCCESS) {
    pthread_mutex_lock(&nm->file_index_lock);
    delete_file_from_trie((TrieNode*)nm->file_index, msg->filename);
    pthread_mutex_unlock(&nm->file_index_lock);
    cache_invalidate(nm->search_cache, msg->filename);  // Remove from cache
        log_message("NM", "Invalidated cache entry for deleted file %s", msg->filename);
        
        // Remove from SS file list
        pthread_mutex_lock(&nm->ss_lock);
        for (int i = 0; i < ss->num_files; i++) {
            if (strcmp(ss->files[i], msg->filename) == 0) {
                free(ss->files[i]);
                for (int j = i; j < ss->num_files - 1; j++) {
                    ss->files[j] = ss->files[j + 1];
                }
                ss->num_files--;
                break;
            }
        }
        pthread_mutex_unlock(&nm->ss_lock);
        
        log_message("NM", "File %s deleted successfully", msg->filename);
    }
}

void handle_file_info(NameServer* nm, int client_fd, FileOpMsg* msg) {
    log_message("NM", "INFO request for %s by %s", msg->filename, msg->username);
    
    // Check if file exists (use cached search)
    FileMetadata* meta = search_file_cached(nm, msg->filename);
    if (meta == NULL) {
        send_error(client_fd, ERR_FILE_NOT_FOUND, 0);
        return;
    }
    
    // Check read access
    if (!check_read_access(meta, msg->username)) {
        send_error(client_fd, ERR_ACCESS_DENIED, 0);
        return;
    }
    
    // Get file content from storage server to get current size
    StorageServer* ss = find_ss_for_file(nm, msg->filename);
    char* content = NULL;
    size_t file_size = 0;
    
    if (ss != NULL) {
        MessageHeader req_header;
        req_header.type = MSG_SS_GET_CONTENT;
        req_header.length = sizeof(FileOpMsg);
        req_header.seq_num = 0;
        
        send(ss->sockfd, &req_header, sizeof(MessageHeader), 0);
        send(ss->sockfd, msg, sizeof(FileOpMsg), 0);
        
        MessageHeader ss_resp;
        if (recv(ss->sockfd, &ss_resp, sizeof(MessageHeader), MSG_WAITALL) == sizeof(MessageHeader)) {
            if (ss_resp.type == MSG_SUCCESS && ss_resp.length > 0) {
                content = (char*)malloc(ss_resp.length);
                recv(ss->sockfd, content, ss_resp.length, MSG_WAITALL);
                file_size = ss_resp.length - 1;  // Exclude null terminator
            }
        }
    }
    
    // Format file information
    char info_buffer[2048];
    char created_str[64], modified_str[64], accessed_str[64];
    
    strftime(created_str, sizeof(created_str), "%Y-%m-%d %H:%M:%S", localtime(&meta->created));
    strftime(modified_str, sizeof(modified_str), "%Y-%m-%d %H:%M:%S", localtime(&meta->last_modified));
    strftime(accessed_str, sizeof(accessed_str), "%Y-%m-%d %H:%M:%S", localtime(&meta->last_accessed));
    
    snprintf(info_buffer, sizeof(info_buffer),
        "========================================\n"
        "File Information: %s\n"
        "========================================\n"
        "Owner: %s\n"
        "Size: %zu bytes\n"
        "Word Count: %d\n"
        "Character Count: %d\n"
        "Created: %s\n"
        "Last Modified: %s\n"
        "Last Accessed: %s\n"
        "\n"
        "Access Rights:\n"
        "  Owner: Read, Write\n",
        msg->filename,
        meta->owner,
        file_size,
        meta->word_count,
        meta->char_count,
        created_str,
        modified_str,
        accessed_str
    );
    
    // Add read users
    if (meta->num_read_users > 0) {
        strncat(info_buffer, "  Read Access: ", sizeof(info_buffer) - strlen(info_buffer) - 1);
        for (int i = 0; i < meta->num_read_users; i++) {
            strncat(info_buffer, meta->read_users[i], sizeof(info_buffer) - strlen(info_buffer) - 1);
            if (i < meta->num_read_users - 1) {
                strncat(info_buffer, ", ", sizeof(info_buffer) - strlen(info_buffer) - 1);
            }
        }
        strncat(info_buffer, "\n", sizeof(info_buffer) - strlen(info_buffer) - 1);
    }
    
    // Add write users
    if (meta->num_write_users > 0) {
        strncat(info_buffer, "  Write Access: ", sizeof(info_buffer) - strlen(info_buffer) - 1);
        for (int i = 0; i < meta->num_write_users; i++) {
            strncat(info_buffer, meta->write_users[i], sizeof(info_buffer) - strlen(info_buffer) - 1);
            if (i < meta->num_write_users - 1) {
                strncat(info_buffer, ", ", sizeof(info_buffer) - strlen(info_buffer) - 1);
            }
        }
        strncat(info_buffer, "\n", sizeof(info_buffer) - strlen(info_buffer) - 1);
    }
    
    strncat(info_buffer, "========================================\n", sizeof(info_buffer) - strlen(info_buffer) - 1);
    
    // Send response
    MessageHeader resp_header;
    resp_header.type = MSG_SUCCESS;
    resp_header.length = strlen(info_buffer) + 1;
    resp_header.seq_num = 0;
    
    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
    send(client_fd, info_buffer, resp_header.length, 0);
    
    if (content != NULL) {
        free(content);
    }
}

void handle_list_users(NameServer* nm, int client_fd) {
    log_message("NM", "LIST_USERS request");
    
    // Collect ALL unique usernames (including disconnected users)
    // AG: "Registered users include users not currently online. You must store all users that have logged in till date."
    pthread_mutex_lock(&nm->client_lock);
    
    int user_count = 0;
    char** usernames = NULL;
    Client* client = nm->client_list;
    
    while (client != NULL) {
        // Check ALL clients, not just active ones
        // Check if username already in list (deduplicate)
        bool found = false;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(usernames[i], client->username) == 0) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            usernames = (char**)realloc(usernames, (user_count + 1) * sizeof(char*));
            usernames[user_count] = (char*)malloc(MAX_USERNAME);
            strncpy(usernames[user_count], client->username, MAX_USERNAME - 1);
            usernames[user_count][MAX_USERNAME - 1] = '\0';
            user_count++;
        }
        
        client = client->next;
    }
    
    pthread_mutex_unlock(&nm->client_lock);
    
    // Format response
    char response_buffer[4096];
    snprintf(response_buffer, sizeof(response_buffer), "Registered Users (%d):\n", user_count);
    
    for (int i = 0; i < user_count; i++) {
        char user_line[128];
        snprintf(user_line, sizeof(user_line), "  %d. %s\n", i + 1, usernames[i]);
        strncat(response_buffer, user_line, sizeof(response_buffer) - strlen(response_buffer) - 1);
    }
    
    // Send response
    MessageHeader resp_header;
    resp_header.type = MSG_SUCCESS;
    resp_header.length = strlen(response_buffer) + 1;
    resp_header.seq_num = 0;
    
    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
    send(client_fd, response_buffer, resp_header.length, 0);
    
    // Cleanup
    for (int i = 0; i < user_count; i++) {
        free(usernames[i]);
    }
    free(usernames);
}

void handle_access_control(NameServer* nm, int client_fd, AccessMsg* msg) {
    log_message("NM", "ACCESS request: %s modifying %s on %s (read=%d, write=%d)",
                msg->username, msg->target_user, msg->filename, msg->read_access, msg->write_access);
    
    // Check if file exists (use cached search)
    FileMetadata* meta = search_file_cached(nm, msg->filename);
    if (meta == NULL) {
        send_error(client_fd, ERR_FILE_NOT_FOUND, 0);
        return;
    }
    
    // Check if requester is owner
    if (strcmp(meta->owner, msg->username) != 0) {
        send_error(client_fd, ERR_NOT_OWNER, 0);
        return;
    }
    
    // Don't allow removing access from owner
    if (strcmp(meta->owner, msg->target_user) == 0) {
        ErrorMsg error;
        error.error_code = ERR_INVALID_PARAMS;
        strncpy(error.message, "Cannot modify owner's access rights", sizeof(error.message) - 1);
        error.message[sizeof(error.message) - 1] = '\0';
        
        MessageHeader resp_header;
        resp_header.type = MSG_ERROR;
        resp_header.length = sizeof(ErrorMsg);
        resp_header.seq_num = 0;
        send(client_fd, &resp_header, sizeof(MessageHeader), 0);
        send(client_fd, &error, sizeof(ErrorMsg), 0);
        return;
    }
    
    // Check if target user is registered
    // AG: "Yes, an unregistered user should ideally not even get access to the interface."
    if (!is_user_registered(nm, msg->target_user)) {
        ErrorMsg error;
        error.error_code = ERR_INVALID_PARAMS;
        snprintf(error.message, sizeof(error.message), "User '%s' is not registered", msg->target_user);
        
        MessageHeader resp_header;
        resp_header.type = MSG_ERROR;
        resp_header.length = sizeof(ErrorMsg);
        resp_header.seq_num = 0;
        send(client_fd, &resp_header, sizeof(MessageHeader), 0);
        send(client_fd, &error, sizeof(ErrorMsg), 0);
        log_error("NM", "Attempt to grant access to unregistered user: %s", msg->target_user);
        return;
    }
    
    // Apply access changes; while holding file_index_lock capture a snapshot of
    // metadata fields we need to send to the Storage Server (ACLs, owner, stats,
    // and primary SS pointer). We MUST not contact SS while holding the lock.
    SSMetadataTransferMsg transfer_msg;
    StorageServer* target_ss = NULL;
    // Prepare empty transfer buffer
    memset(&transfer_msg, 0, sizeof(transfer_msg));

    pthread_mutex_lock(&nm->file_index_lock);
    if (msg->read_access || msg->write_access) {
        // Adding access
        if (msg->write_access) {
            add_write_access(meta, msg->target_user);
        } else if (msg->read_access) {
            add_read_access(meta, msg->target_user);
        }
    } else {
        // Removing access
        remove_access(meta, msg->target_user);
    }

    // Capture primary SS pointer and build flattened ACL strings under the lock
    target_ss = meta->primary_ss;
    strncpy(transfer_msg.filename, meta->filename, MAX_FILENAME - 1);
    strncpy(transfer_msg.owner, meta->owner, MAX_USERNAME - 1);
    transfer_msg.created = meta->created;
    transfer_msg.last_modified = meta->last_modified;
    transfer_msg.last_accessed = meta->last_accessed;
    transfer_msg.size = meta->size;
    transfer_msg.word_count = meta->word_count;
    transfer_msg.char_count = meta->char_count;

    // Build comma-separated read_users and write_users
    transfer_msg.read_users[0] = '\0';
    transfer_msg.write_users[0] = '\0';
    for (int i = 0; i < meta->num_read_users; i++) {
        if (strlen(transfer_msg.read_users) + strlen(meta->read_users[i]) + 2 < MAX_ACL_STRING) {
            if (transfer_msg.read_users[0] != '\0') strncat(transfer_msg.read_users, ",", MAX_ACL_STRING - strlen(transfer_msg.read_users) - 1);
            strncat(transfer_msg.read_users, meta->read_users[i], MAX_ACL_STRING - strlen(transfer_msg.read_users) - 1);
        }
    }
    for (int i = 0; i < meta->num_write_users; i++) {
        if (strlen(transfer_msg.write_users) + strlen(meta->write_users[i]) + 2 < MAX_ACL_STRING) {
            if (transfer_msg.write_users[0] != '\0') strncat(transfer_msg.write_users, ",", MAX_ACL_STRING - strlen(transfer_msg.write_users) - 1);
            strncat(transfer_msg.write_users, meta->write_users[i], MAX_ACL_STRING - strlen(transfer_msg.write_users) - 1);
        }
    }

    pthread_mutex_unlock(&nm->file_index_lock);
    
    // Send success response
    MessageHeader resp_header;
    resp_header.type = MSG_SUCCESS;
    resp_header.length = 0;
    resp_header.seq_num = 0;
    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
    
    log_message("NM", "Access control updated for %s on file %s", msg->target_user, msg->filename);

    // If we have a storage server for this file, notify it about the ACL change
    if (target_ss != NULL) {
        MessageHeader nm_to_ss;
        nm_to_ss.type = MSG_SS_UPDATE_METADATA;
        nm_to_ss.length = sizeof(SSMetadataTransferMsg);
        nm_to_ss.seq_num = 0;

        // Send update to the storage server and wait for ack
        if (send(target_ss->sockfd, &nm_to_ss, sizeof(MessageHeader), 0) == sizeof(MessageHeader) &&
            send(target_ss->sockfd, &transfer_msg, sizeof(SSMetadataTransferMsg), 0) == sizeof(SSMetadataTransferMsg)) {
            MessageHeader ss_resp;
            if (recv(target_ss->sockfd, &ss_resp, sizeof(MessageHeader), MSG_WAITALL) == sizeof(MessageHeader)) {
                if (ss_resp.type == MSG_SUCCESS) {
                    log_message("NM", "Pushed ACL update for %s to SS %s:%d", transfer_msg.filename, target_ss->ip, target_ss->client_port);
                } else {
                    log_error("NM", "SS rejected ACL update for %s", transfer_msg.filename);
                }
            } else {
                log_error("NM", "No ACK from SS when pushing ACL update for %s", transfer_msg.filename);
            }
        } else {
            log_error("NM", "Failed to send ACL update to SS for %s", transfer_msg.filename);
        }
    }
}

void handle_exec(NameServer* nm, int client_fd, FileOpMsg* msg) {
    log_message("NM", "EXEC request for %s by %s", msg->filename, msg->username);
    
    // Check if file exists (use cached search)
    FileMetadata* meta = search_file_cached(nm, msg->filename);
    if (meta == NULL) {
        send_error(client_fd, ERR_FILE_NOT_FOUND, 0);
        return;
    }
    
    // Check read access
    if (!check_read_access(meta, msg->username)) {
        send_error(client_fd, ERR_ACCESS_DENIED, 0);
        return;
    }
    
    // Get file content from storage server
    StorageServer* ss = find_ss_for_file(nm, msg->filename);
    if (ss == NULL) {
        send_error(client_fd, ERR_SS_UNAVAILABLE, 0);
        return;
    }
    
    MessageHeader req_header;
    req_header.type = MSG_SS_GET_CONTENT;
    req_header.length = sizeof(FileOpMsg);
    req_header.seq_num = 0;
    
    send(ss->sockfd, &req_header, sizeof(MessageHeader), 0);
    send(ss->sockfd, msg, sizeof(FileOpMsg), 0);
    
    MessageHeader ss_resp;
    char* content = NULL;
    
    if (recv(ss->sockfd, &ss_resp, sizeof(MessageHeader), MSG_WAITALL) == sizeof(MessageHeader)) {
        if (ss_resp.type == MSG_SUCCESS && ss_resp.length > 0) {
            content = (char*)malloc(ss_resp.length);
            recv(ss->sockfd, content, ss_resp.length, MSG_WAITALL);
        }
    }
    
    if (content == NULL) {
        send_error(client_fd, ERR_INTERNAL, 0);
        log_error("NM", "Failed to read file content from SS for %s", msg->filename);
        return;
    }
    
    // Execute file content as shell commands
    FILE* fp = popen(content, "r");
    if (fp == NULL) {
        send_error(client_fd, ERR_INTERNAL, 0);
        log_error("NM", "Failed to execute command from file %s", msg->filename);
        free(content);
        return;
    }
    
    // Read output
    char output_buffer[8192] = {0};
    size_t output_size = 0;
    char line[1024];
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t line_len = strlen(line);
        if (output_size + line_len < sizeof(output_buffer) - 1) {
            strncpy(output_buffer + output_size, line, sizeof(output_buffer) - output_size - 1);
            output_size += line_len;
        }
    }
    
    int exit_status = pclose(fp);
    
    // Format response with exit status (truncate output_buffer safely)
    char response_buffer[8192];
    int max_print = (int)sizeof(response_buffer) - 128; // leave room for headers
    if (max_print < 0) max_print = 0;
    snprintf(response_buffer, sizeof(response_buffer), "Command Output:\n%.*s\nExit Status: %d\n",
             max_print, output_buffer, exit_status);
    
    // Send response
    MessageHeader resp_header;
    resp_header.type = MSG_SUCCESS;
    resp_header.length = strlen(response_buffer) + 1;
    resp_header.seq_num = 0;
    
    send(client_fd, &resp_header, sizeof(MessageHeader), 0);
    send(client_fd, response_buffer, resp_header.length, 0);
    
    free(content);
    log_message("NM", "Executed file %s, exit status: %d", msg->filename, exit_status);
}
