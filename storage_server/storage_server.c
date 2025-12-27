#define _GNU_SOURCE
#include "storage_server.h"
#include "file_ops.h"
#include "../common/utils.h"
#include "../common/errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

void serialize_users(char** user_list, int count, char* dest) {
    dest[0] = '\0';
    for (int i = 0; i < count; i++) {
        strncat(dest, user_list[i], MAX_ACL_STRING - strlen(dest) - 1);
        if (i < count - 1) {
            strncat(dest, ",", MAX_ACL_STRING - strlen(dest) - 1);
        }
    }
}

// Create directories recursively (mkdir -p equivalent)
static int ss_mkdir_p(const char* path) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, MAX_PATH - 1);
    tmp[MAX_PATH - 1] = '\0';
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';

    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
    return 0;
}

// Clean up locks held by a disconnected client
void cleanup_client_locks(StorageServer* ss, const char* username) {
    pthread_mutex_lock(&ss->locks_mutex);
    
    int removed = 0;
    for (int i = ss->num_locks - 1; i >= 0; i--) {
        if (strcmp(ss->locks[i].locked_by, username) == 0) {
            log_message("SS", "Cleaning up stale lock: %s sentence %d by %s", 
                       ss->locks[i].filename, ss->locks[i].sentence_num, 
                       ss->locks[i].locked_by);
            
            // Remove this lock
            for (int j = i; j < ss->num_locks - 1; j++) {
                ss->locks[j] = ss->locks[j + 1];
            }
            ss->num_locks--;
            removed++;
        }
    }
    
    if (removed > 0) {
        log_message("SS", "Removed %d stale locks for user %s", removed, username);
    }
    
    pthread_mutex_unlock(&ss->locks_mutex);
}

// Check for potential deadlocks (locks held too long)
void check_for_deadlock(StorageServer* ss) {
    static time_t last_check = 0;
    const int CHECK_INTERVAL = 5; // Check every 5 seconds
    const int LOCK_TIMEOUT = 60; // Break locks older than 60 seconds
    time_t now = time(NULL);
    
    if (now - last_check < CHECK_INTERVAL) return;
    last_check = now;
    
    pthread_mutex_lock(&ss->locks_mutex);
    
    for (int i = 0; i < ss->num_locks; i++) {
        // FIX: Check if the lock is actually active
        if (ss->locks[i].locked) {
            time_t lock_age = now - ss->locks[i].locked_at;
            
            // FIX: If lock is held for too long, forcefully release it
            if (lock_age > LOCK_TIMEOUT) {
                log_error("SS", "DEADLOCK DETECTED: Lock on %s sentence %d by %s held for %ld seconds. Forcefully releasing.",
                         ss->locks[i].filename, ss->locks[i].sentence_num, 
                         ss->locks[i].locked_by, lock_age);
                
                // Force-release the lock to un-hang the system
                ss->locks[i].locked = false;
                ss->locks[i].locked_by[0] = '\0';
            }
        }
    }
    
    pthread_mutex_unlock(&ss->locks_mutex);
}

// Initialize storage server
int ss_init(StorageServer* ss, const char* nm_ip, uint16_t nm_port, uint16_t client_port) {
    if (ss == NULL) return -1;
    (void)nm_ip; // nm_ip unused on this platform
    
    strncpy(ss->ip, "127.0.0.1", MAX_IP - 1);
    ss->ip[MAX_IP - 1] = '\0';
    ss->nm_port = nm_port;
    ss->client_port = client_port;
    ss->nm_sockfd = -1;
    ss->client_server_fd = -1;
    
    // Create storage directory
    snprintf(ss->storage_path, MAX_PATH, "./storage_ss_%d", client_port);
    mkdir(ss->storage_path, 0755);
    
    // Initialize locks
    ss->locks = NULL;
    ss->num_locks = 0;
    pthread_mutex_init(&ss->locks_mutex, NULL);
    
    // Initialize per-file commit mutexes
    ss->file_commit_mutexes = NULL;
    ss->num_file_commit_mutexes = 0;
    pthread_mutex_init(&ss->file_commit_mutexes_mutex, NULL);
    
    // Initialize undo states
    for (int i = 0; i < 100; i++) {
        ss->undo_state[i].has_backup = false;
        ss->undo_state[i].prev_content = NULL;
        ss->undo_state[i].filename[0] = '\0';
    }
    
    // Initialize metadata
    ss->file_metadata = NULL;
    ss->num_metadata = 0;
    pthread_mutex_init(&ss->metadata_mutex, NULL);
    
    // Load persistent data from disk
    ss_load_undo_states(ss);
    ss_load_file_metadata(ss);
    
    log_message("SS", "Storage Server initialized at port %d, storage path: %s", 
                client_port, ss->storage_path);
    
    return 0;
}

// Register with Name Server
int ss_register_with_nm(StorageServer* ss) {
    // Connect to Name Server
    ss->nm_sockfd = connect_to_server("127.0.0.1", ss->nm_port);
    if (ss->nm_sockfd < 0) {
        log_error("SS", "Failed to connect to Name Server at port %d", ss->nm_port);
        return -1;
    }
    
    log_message("SS", "Connected to Name Server");
    
    // Scan storage directory for files
    DIR* dir = opendir(ss->storage_path);
    if (dir == NULL) {
        log_error("SS", "Failed to open storage directory");
        close(ss->nm_sockfd);
        return -1;
    }
    
    // Count files (exclude hidden/system files)
    int file_count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;
        if (entry->d_name[0] == '.') continue;
        if (strncmp(entry->d_name, ".meta_", 6) == 0) continue;
        if (strncmp(entry->d_name, ".swap_", 6) == 0) continue;
        if (strncmp(entry->d_name, ".undo_", 6) == 0) continue;
        if (strncmp(entry->d_name, ".hist_", 6) == 0) continue;
        file_count++;
    }
    rewinddir(dir);
    
    // Prepare registration message
    SSRegisterMsg reg_msg;
    strncpy(reg_msg.ip, ss->ip, MAX_IP - 1);
    reg_msg.ip[MAX_IP - 1] = '\0';
    reg_msg.nm_port = ss->nm_port;
    reg_msg.client_port = ss->client_port;
    reg_msg.num_files = file_count;
    
    // Send registration header + message
    MessageHeader header;
    header.type = MSG_SS_REGISTER;
    header.length = sizeof(SSRegisterMsg) + file_count * MAX_FILENAME;
    header.seq_num = 0;
    
    if (send(ss->nm_sockfd, &header, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
        log_error("SS", "Failed to send registration header");
        closedir(dir);
        close(ss->nm_sockfd);
        return -1;
    }
    
    // Send registration message
    if (send(ss->nm_sockfd, &reg_msg, sizeof(SSRegisterMsg), 0) != sizeof(SSRegisterMsg)) {
        log_error("SS", "Failed to send registration message");
        closedir(dir);
        close(ss->nm_sockfd);
        return -1;
    }
    
    // Send file list (only actual user files, not system files)
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;
        if (entry->d_name[0] == '.') continue;
        if (strncmp(entry->d_name, ".meta_", 6) == 0) continue;
        if (strncmp(entry->d_name, ".swap_", 6) == 0) continue;
        if (strncmp(entry->d_name, ".undo_", 6) == 0) continue;
        if (strncmp(entry->d_name, ".hist_", 6) == 0) continue;

        char filename[MAX_FILENAME];
        strncpy(filename, entry->d_name, MAX_FILENAME - 1);
        filename[MAX_FILENAME - 1] = '\0';
        if (send(ss->nm_sockfd, filename, MAX_FILENAME, 0) != MAX_FILENAME) {
            log_error("SS", "Failed to send filename");
        }
        log_message("SS", "  - Sent file: %s", filename);
    }
    closedir(dir);
    
    log_message("SS", "Registration sent with %d files", file_count);
    
    // Wait for acknowledgment
    MessageHeader ack_header;
    if (recv(ss->nm_sockfd, &ack_header, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        log_error("SS", "Failed to receive acknowledgment");
        close(ss->nm_sockfd);
        return -1;
    }
    
    if (ack_header.type == MSG_SUCCESS) {
        log_message("SS", "Successfully registered with Name Server");
        return 0;
    } else {
        log_error("SS", "Registration failed");
        close(ss->nm_sockfd);
        return -1;
    }
}

// Handle Name Server requests
void* handle_nm_requests(void* arg) {
    StorageServer* ss = (StorageServer*)arg;
    
    while (1) {
        MessageHeader header;
        char buffer[BUFFER_SIZE];
        
        int recv_result = recv(ss->nm_sockfd, &header, sizeof(MessageHeader), MSG_WAITALL);
        if (recv_result <= 0) {
            log_error("SS", "Name Server connection lost (will attempt to reconnect)");
            close(ss->nm_sockfd);

            // Attempt to reconnect and re-register in a loop with backoff
            while (1) {
                log_message("SS", "Attempting to reconnect to Name Server...");
                if (ss_register_with_nm(ss) == 0) {
                    log_message("SS", "Reconnected and re-registered with Name Server");
                    break; // successfully re-registered, continue handling requests
                }
                log_error("SS", "Reconnection attempt failed, retrying in 2 seconds");
                sleep(2);
            }

            // After successful reconnection, continue to next loop iteration to recv new header
            continue;
        }
        
        // Receive payload if exists
        if (header.length > 0) {
            if (recv(ss->nm_sockfd, buffer, header.length, MSG_WAITALL) != (ssize_t)header.length) {
                log_error("SS", "Failed to receive payload");
                continue;
            }
        }
        
        // Handle different message types
        switch (header.type) {
            case MSG_PING: {
                // Respond with PONG
                MessageHeader pong = { .type = MSG_PONG, .length = 0, .seq_num = header.seq_num };
                send(ss->nm_sockfd, &pong, sizeof(MessageHeader), 0);
                break;
            }
            case MSG_SS_PULL_FILE: {
                SSReplicateMsg* rmsg = (SSReplicateMsg*)buffer;
                log_message("SS", "PULL_FILE request for %s from %s:%d", rmsg->filename, rmsg->src_ip, rmsg->src_port);

                // Connect to source SS's client port and request file as a client
                int src_fd = connect_to_server(rmsg->src_ip, rmsg->src_port);
                MessageHeader resp_header;
                if (src_fd < 0) {
                    log_error("SS", "Failed to connect to source SS at %s:%d", rmsg->src_ip, rmsg->src_port);
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                    break;
                }

                // Send client-style read request to source SS
                FileOpMsg fop;
                memset(&fop, 0, sizeof(fop));
                strncpy(fop.filename, rmsg->filename, MAX_FILENAME - 1);
                MessageHeader creq = { .type = MSG_CLIENT_READ, .length = sizeof(FileOpMsg), .seq_num = 0 };
                send(src_fd, &creq, sizeof(MessageHeader), 0);
                send(src_fd, &fop, sizeof(FileOpMsg), 0);

                MessageHeader cresp;
                if (recv(src_fd, &cresp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader) || cresp.type != MSG_SUCCESS) {
                    log_error("SS", "Failed to get content from source SS for %s", rmsg->filename);
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                    close(src_fd);
                    break;
                }

                char* content = NULL;
                if (cresp.length > 0) {
                    content = (char*)malloc(cresp.length);
                    recv(src_fd, content, cresp.length, MSG_WAITALL);
                }
                close(src_fd);

                // Write content to local storage path
                char local_path[MAX_PATH];
                snprintf(local_path, MAX_PATH, "%s/%s", ss->storage_path, rmsg->filename);
                // Ensure directories exist
                char* last_slash = strrchr(local_path, '/');
                if (last_slash != NULL) {
                    *last_slash = '\0';
                    ss_mkdir_p(local_path);
                    *last_slash = '/';
                }

                int write_res = -1;
                if (content != NULL) {
                    FILE* out = fopen(local_path, "w");
                    if (out != NULL) {
                        fwrite(content, 1, cresp.length - 1, out); // exclude possible null
                        fclose(out);
                        write_res = 0;
                    }
                } else {
                    // Create empty file
                    FILE* out = fopen(local_path, "w");
                    if (out != NULL) { fclose(out); write_res = 0; }
                }

                if (content) free(content);

                if (write_res == 0) {
                    // Update SS metadata
                    ss_update_file_metadata(ss, rmsg->filename, NULL, 0, 0, 0);
                    resp_header.type = MSG_SUCCESS;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                    log_message("SS", "Pulled and stored %s successfully", rmsg->filename);
                } else {
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                    log_error("SS", "Failed to write pulled file %s", rmsg->filename);
                }
                break;
            }
case MSG_SS_CREATE_FILE: {
    FileOpMsg* msg = (FileOpMsg*)buffer;  // ✅ Use buffer, not recv again!
    
    log_message("SS", "CREATE request for %s by %s", msg->filename, msg->username);
    int result = ss_create_file(ss, msg->filename);
    
    if (result == 0) {
        ss_update_file_metadata(ss, msg->filename, msg->username, 0, 0, 0);
    }
    
    MessageHeader resp_header;
    resp_header.type = (result == 0) ? MSG_SUCCESS : MSG_ERROR;
    resp_header.length = 0;
    resp_header.seq_num = header.seq_num;
    
    ssize_t sent = send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
    if (sent != sizeof(MessageHeader)) {
        log_error("SS", "Failed to send CREATE response: %zd bytes", sent);
    }
    log_message("SS", "Sent CREATE response: %zd bytes", sent);
        if (result == 0) {
            HistoryEntry e;
            memset(&e, 0, sizeof(e));
            char* ts = get_timestamp();
            if (ts) strncpy(e.timestamp, ts, sizeof(e.timestamp)-1);
            strncpy(e.username, msg->username, MAX_USERNAME-1);
            strncpy(e.op_type, "create", sizeof(e.op_type)-1);
            e.lines_added = 0; e.lines_removed = 0; e.chars_added = 0; e.chars_removed = 0;
            ss_append_history_entry(ss, msg->filename, &e);
        }
    break;
}
            case MSG_SS_DELETE_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("SS", "DELETE request for %s", msg->filename);
                
                int result = ss_delete_file(ss, msg->filename);
                
                MessageHeader resp_header;
                resp_header.type = (result == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp_header.length = 0;
                resp_header.seq_num = header.seq_num;
                
                send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                if (result == 0) {
                    HistoryEntry e;
                    memset(&e,0,sizeof(e));
                    char* ts = get_timestamp(); if (ts) strncpy(e.timestamp, ts, sizeof(e.timestamp)-1);
                    strncpy(e.username, msg->username, MAX_USERNAME-1);
                    strncpy(e.op_type, "delete", sizeof(e.op_type)-1);
                    ss_append_history_entry(ss, msg->filename, &e);
                }
                break;
            }
            case MSG_SS_CREATE_FOLDER: {
                CreateFolderMsg* msg = (CreateFolderMsg*)buffer;
                log_message("SS", "CREATE_FOLDER request for %s by %s", msg->foldername, msg->username);

                // Construct full path under storage path
                char fullpath[MAX_PATH];
                snprintf(fullpath, MAX_PATH, "%s/%s", ss->storage_path, msg->foldername);

                int res = ss_mkdir_p(fullpath);

                MessageHeader resp;
                resp.type = (res == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                resp.seq_num = header.seq_num;
                send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                if (res == 0) {
                    HistoryEntry e;
                    memset(&e,0,sizeof(e));
                    char* ts = get_timestamp(); if (ts) strncpy(e.timestamp, ts, sizeof(e.timestamp)-1);
                    strncpy(e.username, msg->username, MAX_USERNAME-1);
                    strncpy(e.op_type, "create_folder", sizeof(e.op_type)-1);
                    ss_append_history_entry(ss, msg->foldername, &e);
                }
                break;
            }
            
            case MSG_SS_GET_CONTENT: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("SS", "GET_CONTENT request for %s", msg->filename);
                
                char* content = NULL;
                int result = ss_read_file(ss, msg->filename, &content);
                
                MessageHeader resp_header;
                if (result == 0 && content != NULL) {
                    resp_header.type = MSG_SUCCESS;
                    resp_header.length = strlen(content) + 1;
                    resp_header.seq_num = header.seq_num;
                    
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                    send(ss->nm_sockfd, content, resp_header.length, 0);
                    free(content);
                } else {
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    resp_header.seq_num = header.seq_num;
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                }
                break;
            }
            case MSG_SS_CREATE_CHECKPOINT: {
                CheckpointMsg* msg = (CheckpointMsg*)buffer;
                log_message("SS", "CREATE_CHECKPOINT for %s tag=%s by %s", msg->filename, msg->tag, msg->username);

                // Build paths
                char src_path[MAX_PATH];
                char chk_path[MAX_PATH];
                snprintf(src_path, MAX_PATH, "%s/%s", ss->storage_path, msg->filename);
                // Sanitize tag to avoid path traversal (simple: allow alnum and _)
                char safe_tag[64];
                int si = 0;
                for (int i = 0; msg->tag[i] && si < (int)sizeof(safe_tag)-1; i++) {
                    char c = msg->tag[i];
                    if ((c >= 'a' && c <= 'z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') || c=='_' || c=='-') safe_tag[si++] = c;
                }
                safe_tag[si] = '\0';
                snprintf(chk_path, MAX_PATH, "%s/.chk_%s_%s", ss->storage_path, msg->filename, safe_tag);

                // Copy file to checkpoint
                int res = -1;
                FILE* in = fopen(src_path, "r");
                if (in != NULL) {
                    FILE* out = fopen(chk_path, "w");
                    if (out != NULL) {
                        char buf[4096];
                        size_t n;
                        while ((n = fread(buf,1,sizeof(buf),in)) > 0) fwrite(buf,1,n,out);
                        fclose(out);
                        res = 0;
                    }
                    fclose(in);
                }

                MessageHeader resp;
                resp.type = (res == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                resp.seq_num = header.seq_num;
                send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                break;
            }

            case MSG_SS_LIST_CHECKPOINTS: {
                CheckpointListReq* msg = (CheckpointListReq*)buffer;
                log_message("SS", "LIST_CHECKPOINTS for %s by %s", msg->filename, msg->username);

                // Scan storage directory for .chk_<filename>_* entries
                DIR* dir = opendir(ss->storage_path);
                char listbuf[BUFFER_SIZE];
                listbuf[0] = '\0';
                if (dir != NULL) {
                    struct dirent* entry;
                    (void)strlen(".chk_");
                    while ((entry = readdir(dir)) != NULL) {
                        if (entry->d_type == DT_REG) {
                            if (strncmp(entry->d_name, ".chk_", 5) == 0) {
                                // pattern: .chk_<filename>_<tag>
                                const char* rest = entry->d_name + 5;
                                // check filename match
                                size_t fname_len = strlen(msg->filename);
                                if (strncmp(rest, msg->filename, fname_len) == 0 && rest[fname_len] == '_') {
                                    const char* tag = rest + fname_len + 1;
                                    if (strlen(listbuf) + strlen(tag) + 2 < BUFFER_SIZE) {
                                        if (listbuf[0] != '\0') strcat(listbuf, "\n");
                                        strcat(listbuf, tag);
                                    }
                                }
                            }
                        }
                    }
                    closedir(dir);
                }

                MessageHeader resp;
                resp.type = MSG_SUCCESS;
                resp.length = strlen(listbuf) + 1;
                resp.seq_num = header.seq_num;
                send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                if (resp.length > 0) send(ss->nm_sockfd, listbuf, resp.length, 0);
                break;
            }

            case MSG_HISTORY_REQUEST: {
                HistoryReq* msg = (HistoryReq*)buffer;
                log_message("SS", "HISTORY request for %s (max=%d) by NM", msg->filename, msg->max_entries);

                HistoryEntry* entries = NULL;
                int count = 0;
                int res = ss_get_history_entries(ss, msg->filename, &entries, &count, msg->max_entries > 0 ? msg->max_entries : 10);

                MessageHeader resp;
                resp.type = MSG_HISTORY_RESPONSE;
                resp.seq_num = header.seq_num;
                if (res == 0 && count > 0) {
                    // Send HistoryResp (entries_count) then entries
                    HistoryResp hresp;
                    hresp.entries_count = count;
                    resp.length = sizeof(HistoryResp) + count * sizeof(HistoryEntry);
                    if (send_with_retry(ss->nm_sockfd, &resp, sizeof(MessageHeader), 3) < 0) {
                        log_error("SS", "HISTORY: failed to send header to NM for %s", msg->filename);
                    } else {
                        if (send_with_retry(ss->nm_sockfd, &hresp, sizeof(HistoryResp), 3) < 0) {
                            log_error("SS", "HISTORY: failed to send HistoryResp for %s", msg->filename);
                        } else {
                            if (send_with_retry(ss->nm_sockfd, entries, count * sizeof(HistoryEntry), 3) < 0) {
                                log_error("SS", "HISTORY: failed to send entries for %s", msg->filename);
                            }
                        }
                    }
                } else {
                    // No entries - send empty response
                    HistoryResp hresp;
                    hresp.entries_count = 0;
                    resp.length = sizeof(HistoryResp);
                    if (send_with_retry(ss->nm_sockfd, &resp, sizeof(MessageHeader), 3) < 0) {
                        log_error("SS", "HISTORY: failed to send empty header to NM for %s", msg->filename);
                    } else {
                        if (send_with_retry(ss->nm_sockfd, &hresp, sizeof(HistoryResp), 3) < 0) {
                            log_error("SS", "HISTORY: failed to send empty HistoryResp for %s", msg->filename);
                        }
                    }
                }

                if (entries) free(entries);
                break;
            }

            case MSG_SS_VIEW_CHECKPOINT: {
                CheckpointMsg* msg = (CheckpointMsg*)buffer;
                log_message("SS", "VIEW_CHECKPOINT for %s tag=%s by %s", msg->filename, msg->tag, msg->username);

                // Build checkpoint path
                char chk_path[MAX_PATH];
                // Sanitize tag similar to create
                char safe_tag[64];
                int si = 0;
                for (int i = 0; msg->tag[i] && si < (int)sizeof(safe_tag)-1; i++) {
                    char c = msg->tag[i];
                    if ((c >= 'a' && c <= 'z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') || c=='_' || c=='-') safe_tag[si++] = c;
                }
                safe_tag[si] = '\0';
                snprintf(chk_path, MAX_PATH, "%s/.chk_%s_%s", ss->storage_path, msg->filename, safe_tag);

                // Read checkpoint file
                MessageHeader resp;
                FILE* in = fopen(chk_path, "r");
                if (in != NULL) {
                    // Determine size
                    fseek(in, 0, SEEK_END);
                    long sz = ftell(in);
                    fseek(in, 0, SEEK_SET);
                    if (sz < 0) sz = 0;
                    if (sz > 0 && sz < BUFFER_SIZE) {
                        char* content = (char*)malloc(sz + 1);
                        if (fread(content, 1, sz, in) == (size_t)sz) {
                            content[sz] = '\0';
                            resp.type = MSG_SUCCESS;
                            resp.length = (uint32_t)(sz + 1);
                            resp.seq_num = header.seq_num;
                            send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                            send(ss->nm_sockfd, content, resp.length, 0);
                        } else {
                            resp.type = MSG_ERROR;
                            resp.length = 0;
                            resp.seq_num = header.seq_num;
                            send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                        }
                        free(content);
                    } else if (sz == 0) {
                        // Empty file
                        resp.type = MSG_SUCCESS;
                        resp.length = 1;
                        resp.seq_num = header.seq_num;
                        char empty = '\0';
                        send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                        send(ss->nm_sockfd, &empty, 1, 0);
                    } else {
                        // Too large or error
                        resp.type = MSG_ERROR;
                        resp.length = 0;
                        resp.seq_num = header.seq_num;
                        send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                    }
                    fclose(in);
                } else {
                    resp.type = MSG_ERROR;
                    resp.length = 0;
                    resp.seq_num = header.seq_num;
                    send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                }
                break;
            }

            case MSG_SS_REVERT_CHECKPOINT: {
                CheckpointMsg* msg = (CheckpointMsg*)buffer;
                log_message("SS", "REVERT_CHECKPOINT for %s tag=%s by %s", msg->filename, msg->tag, msg->username);

                // Sanitize tag
                char safe_tag[64];
                int si = 0;
                for (int i = 0; msg->tag[i] && si < (int)sizeof(safe_tag)-1; i++) {
                    char c = msg->tag[i];
                    if ((c >= 'a' && c <= 'z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') || c=='_' || c=='-') safe_tag[si++] = c;
                }
                safe_tag[si] = '\0';

                char chk_path[MAX_PATH];
                snprintf(chk_path, MAX_PATH, "%s/.chk_%s_%s", ss->storage_path, msg->filename, safe_tag);

                // Open checkpoint and write to live file
                MessageHeader resp;
                FILE* in = fopen(chk_path, "r");
                if (in == NULL) {
                    log_error("SS", "REVERT: checkpoint %s not found", chk_path);
                    resp.type = MSG_ERROR;
                    resp.length = 0;
                    resp.seq_num = header.seq_num;
                    send_with_retry(ss->nm_sockfd, &resp, sizeof(MessageHeader), 3);
                    break;
                }

                char live_path[MAX_PATH];
                snprintf(live_path, MAX_PATH, "%s/%s", ss->storage_path, msg->filename);

                // Ensure directory exists
                char* last_slash = strrchr(live_path, '/');
                if (last_slash != NULL) {
                    *last_slash = '\0';
                    ss_mkdir_p(live_path);
                    *last_slash = '/';
                }

                FILE* out = fopen(live_path, "w");
                if (out == NULL) {
                    fclose(in);
                    log_error("SS", "REVERT: failed to open live file %s for writing", live_path);
                    resp.type = MSG_ERROR;
                    resp.length = 0;
                    resp.seq_num = header.seq_num;
                    send_with_retry(ss->nm_sockfd, &resp, sizeof(MessageHeader), 3);
                    break;
                }

                char buf[4096];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
                    if (fwrite(buf, 1, n, out) != n) {
                        log_error("SS", "REVERT: write error while restoring %s", live_path);
                        fclose(in);
                        fclose(out);
                        resp.type = MSG_ERROR;
                        resp.length = 0;
                        resp.seq_num = header.seq_num;
                        send_with_retry(ss->nm_sockfd, &resp, sizeof(MessageHeader), 3);
                        goto revert_done;
                    }
                }

                // Flush and fsync to ensure durability
                fflush(out);
                int fd = fileno(out);
                if (fd >= 0) fsync(fd);
                fclose(in);
                fclose(out);

                // Update metadata (size unknown here - let ss_update_file_metadata compute timestamps)
                struct stat st;
                size_t new_size = 0;
                if (stat(live_path, &st) == 0) new_size = (size_t)st.st_size;
                ss_update_file_metadata(ss, msg->filename, NULL, 0, 0, new_size);

                resp.type = MSG_SUCCESS;
                resp.length = 0;
                resp.seq_num = header.seq_num;
                    if (send_with_retry(ss->nm_sockfd, &resp, sizeof(MessageHeader), 3) < 0) {
                        log_error("SS", "REVERT: failed to send reply to NM for %s", msg->filename);
                    }
                log_message("SS", "REVERT_CHECKPOINT applied for %s (tag=%s)", msg->filename, msg->tag);
                // record history for revert
                HistoryEntry e;
                memset(&e,0,sizeof(e));
                char* ts = get_timestamp(); if (ts) strncpy(e.timestamp, ts, sizeof(e.timestamp)-1);
                strncpy(e.username, msg->username, MAX_USERNAME-1);
                strncpy(e.op_type, "revert", sizeof(e.op_type)-1);
                ss_append_history_entry(ss, msg->filename, &e);
revert_done:
                break;
            }

            
            case MSG_SS_MOVE_FILE: {
                MoveFileMsg* msg = (MoveFileMsg*)buffer;
                log_message("SS", "MOVE_FILE request: %s -> %s by %s", msg->src, msg->dst, msg->username);

                char src_path[MAX_PATH];
                char dst_path[MAX_PATH];
                snprintf(src_path, MAX_PATH, "%s/%s", ss->storage_path, msg->src);
                snprintf(dst_path, MAX_PATH, "%s/%s", ss->storage_path, msg->dst);

                // Ensure destination directory exists
                char dst_dir[MAX_PATH];
                strncpy(dst_dir, dst_path, MAX_PATH - 1);
                dst_dir[MAX_PATH - 1] = '\0';
                char* last_slash = strrchr(dst_dir, '/');
                if (last_slash != NULL) {
                    *last_slash = '\0';
                    ss_mkdir_p(dst_dir);
                }

                int rename_res = rename(src_path, dst_path);

                // Update metadata if present
                pthread_mutex_lock(&ss->metadata_mutex);
                SSFileMetadata* found = NULL;
                for (int i = 0; i < ss->num_metadata; i++) {
                    if (strcmp(ss->file_metadata[i].filename, msg->src) == 0) {
                        found = &ss->file_metadata[i];
                        break;
                    }
                }
                if (found != NULL) {
                    // rename metadata on disk: save new metadata and remove old file
                    char old_meta_path[MAX_PATH];
                    snprintf(old_meta_path, MAX_PATH, "%s/.meta_%s", ss->storage_path, found->filename);

                    strncpy(found->filename, msg->dst, MAX_FILENAME - 1);
                    found->filename[MAX_FILENAME - 1] = '\0';
                    ss_save_file_metadata(ss, found->filename, found);
                    // remove old meta file if exists
                    remove(old_meta_path);
                }
                pthread_mutex_unlock(&ss->metadata_mutex);

                MessageHeader resp;
                resp.type = (rename_res == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                resp.seq_num = header.seq_num;
                send(ss->nm_sockfd, &resp, sizeof(MessageHeader), 0);
                break;
            }
            case MSG_SS_GET_METADATA: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("SS", "GET_METADATA request for %s", msg->filename);

                SSFileMetadata* meta = ss_get_file_metadata(ss, msg->filename);
                MessageHeader resp_header;

                if (meta != NULL) {
                    // Prepare the network-safe transfer message
                    SSMetadataTransferMsg transfer_msg;
                    memset(&transfer_msg, 0, sizeof(SSMetadataTransferMsg));

                    strncpy(transfer_msg.filename, meta->filename, MAX_FILENAME - 1);
                    strncpy(transfer_msg.owner, meta->owner, MAX_USERNAME - 1);
                    transfer_msg.created = meta->created;
                    transfer_msg.last_modified = meta->last_modified;
                    transfer_msg.last_accessed = meta->last_accessed;
                    transfer_msg.size = meta->size;
                    transfer_msg.word_count = meta->word_count;
                    transfer_msg.char_count = meta->char_count;

                    // Serialize the user lists into strings
                    serialize_users(meta->read_users, meta->num_read_users, transfer_msg.read_users);
                    serialize_users(meta->write_users, meta->num_write_users, transfer_msg.write_users);

                    resp_header.type = MSG_SUCCESS;
                    resp_header.length = sizeof(SSMetadataTransferMsg);
                    
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                    send(ss->nm_sockfd, &transfer_msg, sizeof(SSMetadataTransferMsg), 0);
                    log_message("SS", "Sent flattened metadata for %s to NM", msg->filename);
                } else {
                    resp_header.type = MSG_ERROR;
                    resp_header.length = 0;
                    send(ss->nm_sockfd, &resp_header, sizeof(MessageHeader), 0);
                    log_error("SS", "Could not find metadata for %s", msg->filename);
                }
                break;
            }
            case MSG_SS_UPDATE_METADATA: {
                SSMetadataTransferMsg* tmsg = (SSMetadataTransferMsg*)buffer;
                log_message("SS", "UPDATE_METADATA request for %s", tmsg->filename);
                // We'll detect newly added users (read/write) and record history entries for grants.
                char** old_read = NULL; int old_read_count = 0;
                char** old_write = NULL; int old_write_count = 0;
                char** new_read_copy = NULL; int new_read_count = 0;
                char** new_write_copy = NULL; int new_write_count = 0;

                // Find or create metadata entry and capture old ACL lists
                pthread_mutex_lock(&ss->metadata_mutex);
                SSFileMetadata* meta = NULL;
                for (int i = 0; i < ss->num_metadata; i++) {
                    if (strcmp(ss->file_metadata[i].filename, tmsg->filename) == 0) {
                        meta = &ss->file_metadata[i];
                        break;
                    }
                }

                if (meta == NULL) {
                    // Create new metadata entry
                    ss->file_metadata = (SSFileMetadata*)realloc(ss->file_metadata, (ss->num_metadata + 1) * sizeof(SSFileMetadata));
                    meta = &ss->file_metadata[ss->num_metadata];
                    memset(meta, 0, sizeof(SSFileMetadata));
                    strncpy(meta->filename, tmsg->filename, MAX_FILENAME - 1);
                    meta->filename[MAX_FILENAME - 1] = '\0';
                    meta->read_users = NULL;
                    meta->num_read_users = 0;
                    meta->write_users = NULL;
                    meta->num_write_users = 0;
                    ss->num_metadata++;
                } else {
                    // Copy old lists for diffing
                    if (meta->num_read_users > 0) {
                        old_read = (char**)malloc(meta->num_read_users * sizeof(char*));
                        for (int j = 0; j < meta->num_read_users; j++) old_read[j] = strdup(meta->read_users[j]);
                        old_read_count = meta->num_read_users;
                    }
                    if (meta->num_write_users > 0) {
                        old_write = (char**)malloc(meta->num_write_users * sizeof(char*));
                        for (int j = 0; j < meta->num_write_users; j++) old_write[j] = strdup(meta->write_users[j]);
                        old_write_count = meta->num_write_users;
                    }

                    // Free existing user lists to replace
                    for (int j = 0; j < meta->num_read_users; j++) free(meta->read_users[j]);
                    free(meta->read_users);
                    for (int j = 0; j < meta->num_write_users; j++) free(meta->write_users[j]);
                    free(meta->write_users);
                    meta->read_users = NULL;
                    meta->write_users = NULL;
                    meta->num_read_users = 0;
                    meta->num_write_users = 0;
                }

                // Copy simple fields
                strncpy(meta->owner, tmsg->owner, MAX_USERNAME - 1);
                meta->owner[MAX_USERNAME - 1] = '\0';
                meta->created = tmsg->created;
                meta->last_modified = tmsg->last_modified;
                meta->last_accessed = tmsg->last_accessed;
                meta->size = tmsg->size;
                meta->word_count = tmsg->word_count;
                meta->char_count = tmsg->char_count;

                // Parse read_users CSV and also build a copy for diffing
                if (tmsg->read_users[0] != '\0') {
                    char tmp[MAX_ACL_STRING];
                    strncpy(tmp, tmsg->read_users, MAX_ACL_STRING - 1);
                    tmp[MAX_ACL_STRING - 1] = '\0';
                    char* saveptr;
                    char* token = strtok_r(tmp, ",", &saveptr);
                    while (token != NULL) {
                        meta->read_users = (char**)realloc(meta->read_users, (meta->num_read_users + 1) * sizeof(char*));
                        meta->read_users[meta->num_read_users] = strdup(token);
                        meta->num_read_users++;

                        new_read_copy = (char**)realloc(new_read_copy, (new_read_count + 1) * sizeof(char*));
                        new_read_copy[new_read_count++] = strdup(token);
                        token = strtok_r(NULL, ",", &saveptr);
                    }
                }

                // Parse write_users CSV and also build a copy for diffing
                if (tmsg->write_users[0] != '\0') {
                    char tmpw[MAX_ACL_STRING];
                    strncpy(tmpw, tmsg->write_users, MAX_ACL_STRING - 1);
                    tmpw[MAX_ACL_STRING - 1] = '\0';
                    char* saveptrw;
                    char* tokenw = strtok_r(tmpw, ",", &saveptrw);
                    while (tokenw != NULL) {
                        meta->write_users = (char**)realloc(meta->write_users, (meta->num_write_users + 1) * sizeof(char*));
                        meta->write_users[meta->num_write_users] = strdup(tokenw);
                        meta->num_write_users++;

                        new_write_copy = (char**)realloc(new_write_copy, (new_write_count + 1) * sizeof(char*));
                        new_write_copy[new_write_count++] = strdup(tokenw);
                        tokenw = strtok_r(NULL, ",", &saveptrw);
                    }
                }

                pthread_mutex_unlock(&ss->metadata_mutex);

                // Persist metadata to disk (ss_save_file_metadata handles disk I/O)
                int res = ss_save_file_metadata(ss, meta->filename, meta);

                // Reply to NM after persisting
                MessageHeader reply;
                reply.type = (res == 0) ? MSG_SUCCESS : MSG_ERROR;
                reply.length = 0;
                reply.seq_num = header.seq_num;
                send(ss->nm_sockfd, &reply, sizeof(MessageHeader), 0);

                // Determine added users by comparing new_*_copy with old_* and record history entries
                if (new_read_count > 0) {
                    for (int i = 0; i < new_read_count; i++) {
                        char* u = new_read_copy[i];
                        bool found = false;
                        for (int j = 0; j < old_read_count; j++) {
                            if (strcmp(u, old_read[j]) == 0) { found = true; break; }
                        }
                        if (!found) {
                            HistoryEntry e;
                            memset(&e, 0, sizeof(e));
                            char* ts = get_timestamp(); if (ts) strncpy(e.timestamp, ts, sizeof(e.timestamp)-1);
                            // Use owner as the actor (transfer_msg.owner)
                            strncpy(e.username, tmsg->owner, MAX_USERNAME-1);
                            strncpy(e.op_type, "grant_read", sizeof(e.op_type)-1);
                            snprintf(e.comment, sizeof(e.comment), "granted READ to %s", u);
                            ss_append_history_entry(ss, tmsg->filename, &e);
                        }
                    }
                }

                if (new_write_count > 0) {
                    for (int i = 0; i < new_write_count; i++) {
                        char* u = new_write_copy[i];
                        bool found = false;
                        for (int j = 0; j < old_write_count; j++) {
                            if (strcmp(u, old_write[j]) == 0) { found = true; break; }
                        }
                        if (!found) {
                            HistoryEntry e;
                            memset(&e, 0, sizeof(e));
                            char* ts = get_timestamp(); if (ts) strncpy(e.timestamp, ts, sizeof(e.timestamp)-1);
                            strncpy(e.username, tmsg->owner, MAX_USERNAME-1);
                            strncpy(e.op_type, "grant_write", sizeof(e.op_type)-1);
                            snprintf(e.comment, sizeof(e.comment), "granted WRITE to %s", u);
                            ss_append_history_entry(ss, tmsg->filename, &e);
                        }
                    }
                }

                // Cleanup temporary copies
                if (old_read) {
                    for (int i = 0; i < old_read_count; i++) free(old_read[i]);
                    free(old_read);
                }
                if (old_write) {
                    for (int i = 0; i < old_write_count; i++) free(old_write[i]);
                    free(old_write);
                }
                if (new_read_copy) {
                    for (int i = 0; i < new_read_count; i++) free(new_read_copy[i]);
                    free(new_read_copy);
                }
                if (new_write_copy) {
                    for (int i = 0; i < new_write_count; i++) free(new_write_copy[i]);
                    free(new_write_copy);
                }

                log_message("SS", "Processed UPDATE_METADATA for %s (persist=%d)", tmsg->filename, res == 0);
                break;
            }
            
            default:
                log_error("SS", "Unknown message type: %d", header.type);
                break;
        }
    }
    
    return NULL;
}

// Structure to pass both SS and client_fd to thread
typedef struct {
    StorageServer* ss;
    int client_fd;
    struct sockaddr_in client_addr;
} ClientThreadArgs;

// Forward declaration
void* handle_client_requests(void* arg);

// Start storage server
void ss_start(StorageServer* ss) {
    // Create server socket for client connections
    ss->client_server_fd = create_tcp_socket();
    if (ss->client_server_fd < 0) {
        log_error("SS", "Failed to create client server socket");
        return;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(ss->client_port);
    
    if (bind(ss->client_server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_error("SS", "Failed to bind client server socket");
        close(ss->client_server_fd);
        return;
    }
    
    if (listen(ss->client_server_fd, 10) < 0) {
        log_error("SS", "Failed to listen on client server socket");
        close(ss->client_server_fd);
        return;
    }
    
    log_message("SS", "Listening for client connections on port %d", ss->client_port);
    
    // Start thread to handle NM requests
    pthread_t nm_thread;
    pthread_create(&nm_thread, NULL, handle_nm_requests, ss);
    
    // Main loop: accept client connections and spawn threads
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(ss->client_server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            log_error("SS", "Failed to accept client connection");
            continue;
        }
        
        // Create thread args and spawn a new thread for this client
        ClientThreadArgs* args = (ClientThreadArgs*)malloc(sizeof(ClientThreadArgs));
        args->ss = ss;
        args->client_fd = client_fd;
        args->client_addr = client_addr;
        
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client_requests, args) != 0) {
            log_error("SS", "Failed to create thread for client (fd=%d)", client_fd);
            close(client_fd);
            free(args);
            continue;
        }
        
        // Detach thread so it cleans up automatically when done
        pthread_detach(client_thread);
        
        log_message("SS", "Spawned thread for client (fd=%d)", client_fd);
    }
}

// Handle client requests in a separate thread
void* handle_client_requests(void* arg) {
    ClientThreadArgs* args = (ClientThreadArgs*)arg;
    StorageServer* ss = args->ss;
    int client_fd = args->client_fd;
    struct sockaddr_in client_addr = args->client_addr;
    free(args);  // Free the args struct
    
    log_message("SS", "Client connected from %s:%d (fd=%d)", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_fd);
    
    // Handle client requests in a loop
    MessageHeader header;
    char buffer[BUFFER_SIZE];
    bool keep_alive = true;
    char current_username[MAX_USERNAME] = {0};
    
    while (keep_alive) {
        // Check for potential deadlocks periodically
        check_for_deadlock(ss);
        
        log_message("SS", "Waiting for message from client (fd=%d)", client_fd);
        int recv_result = recv(client_fd, &header, sizeof(MessageHeader), MSG_WAITALL);
        
        if (recv_result != sizeof(MessageHeader)) {
            if (recv_result < 0) {
                log_error("SS", "Error receiving from client (fd=%d): %s", client_fd, strerror(errno));
            } else if (recv_result == 0) {
                log_message("SS", "Client disconnected (fd=%d)", client_fd);
            } else {
                log_error("SS", "Partial header received from client (fd=%d): %d bytes", client_fd, recv_result);
            }
            break;
        }
        
        log_message("SS", "Received message type %d, length %d (fd=%d)", header.type, header.length, client_fd);
        
        if (header.length > 0) {
            if (header.length >= BUFFER_SIZE) {
                log_error("SS", "Message too large: %d bytes (fd=%d)", header.length, client_fd);
                break;
            }
            
            int recv_payload = recv(client_fd, buffer, header.length, MSG_WAITALL);
            if (recv_payload != (ssize_t)header.length) {
                log_error("SS", "Failed to receive complete payload (fd=%d): expected %d, got %d", 
                         client_fd, header.length, recv_payload);
                break;
            }
            log_message("SS", "Received payload: %d bytes (fd=%d)", recv_payload, client_fd);
        }
        
        MessageHeader resp;
        resp.seq_num = header.seq_num;
        
        switch (header.type) {
            case MSG_CLIENT_READ: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("SS", "READ: %s by %s (fd=%d)", msg->filename, msg->username, client_fd);
                strncpy(current_username, msg->username, MAX_USERNAME - 1);
                
                char* content = NULL;
                int result = ss_read_file(ss, msg->filename, &content);
                
                if (result == 0 && content != NULL) {
                    resp.type = MSG_SUCCESS;
                    resp.length = strlen(content) + 1;
                    log_message("SS", "READ success, sending %d bytes (fd=%d)", resp.length, client_fd);
                    send(client_fd, &resp, sizeof(MessageHeader), 0);
                    send(client_fd, content, resp.length, 0);
                    free(content);
                } else {
                    log_error("SS", "READ failed for %s (fd=%d)", msg->filename, client_fd);
                    resp.type = MSG_ERROR;
                    resp.length = 0;
                    send(client_fd, &resp, sizeof(MessageHeader), 0);
                }
                keep_alive = false; // Close after READ
                break;
            }
            
            case MSG_WRITE_START: {
                WriteStartMsg* msg = (WriteStartMsg*)buffer;
                log_message("SS", "WRITE_START: %s sentence %d by %s (fd=%d)", 
                           msg->filename, msg->sentence_num, msg->username, client_fd);
                strncpy(current_username, msg->username, MAX_USERNAME - 1);
                
                int result = ss_write_start(ss, msg->filename, msg->sentence_num, msg->username);
                
                resp.type = (result == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                
                log_message("SS", "WRITE_START %s, sending response (fd=%d)", 
                           (result == 0) ? "SUCCESS" : "FAILED", client_fd);
                
                if (send(client_fd, &resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("SS", "Failed to send WRITE_START response (fd=%d)", client_fd);
                    keep_alive = false;
                }
                break;
            }
            
            case MSG_WRITE_UPDATE: {
                WriteUpdateMsg* msg = (WriteUpdateMsg*)buffer;
                log_message("SS", "WRITE_UPDATE: %s sentence %d, word %d = '%s' (fd=%d)", 
                           msg->filename, msg->sentence_num, msg->word_index, msg->content, client_fd);
                
                int result = ss_write_update(ss, msg->filename, msg->sentence_num, 
                                             msg->word_index, msg->content);
                
                resp.type = (result == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                
                log_message("SS", "WRITE_UPDATE %s, sending response (fd=%d)", 
                           (result == 0) ? "SUCCESS" : "FAILED", client_fd);
                
                if (send(client_fd, &resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("SS", "Failed to send WRITE_UPDATE response (fd=%d)", client_fd);
                    keep_alive = false;
                }
                // Record history for successful word update: capture which word index and the user
                if (result == 0) {
                    HistoryEntry e;
                    memset(&e, 0, sizeof(e));
                    char* ts = get_timestamp(); if (ts) strncpy(e.timestamp, ts, sizeof(e.timestamp)-1);
                    strncpy(e.username, current_username, MAX_USERNAME-1);
                    strncpy(e.op_type, "write", sizeof(e.op_type)-1);
                    e.lines_added = 0; e.lines_removed = 0;
                    e.chars_added = (int)strlen(msg->content);
                    e.chars_removed = 0;
                    // Comment: record word index and a short preview of content (truncate)
                    char preview[128];
                    int len = snprintf(preview, sizeof(preview), "word=%d '%s'", msg->word_index, msg->content);
                    if (len >= (int)sizeof(preview)) preview[sizeof(preview)-1] = '\0';
                    strncpy(e.comment, preview, sizeof(e.comment)-1);
                    // Append outside of any metadata locks (this handler is already outside)
                    ss_append_history_entry(ss, msg->filename, &e);
                }
                break;
            }
            
            case MSG_WRITE_END: {
                WriteEndMsg* msg = (WriteEndMsg*)buffer;
                log_message("SS", "WRITE_END: %s sentence %d (fd=%d)", msg->filename, msg->sentence_num, client_fd);
                
                int result = ss_write_end(ss, msg->filename, msg->sentence_num);
                
                resp.type = (result == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                
                log_message("SS", "WRITE_END %s, sending response (fd=%d)", 
                           (result == 0) ? "SUCCESS" : "FAILED", client_fd);
                
                if (send(client_fd, &resp, sizeof(MessageHeader), 0) != sizeof(MessageHeader)) {
                    log_error("SS", "Failed to send WRITE_END response (fd=%d)", client_fd);
                }
                
                keep_alive = false; // Close after WRITE_END
                break;
            }
            
            case MSG_CLIENT_STREAM: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("SS", "STREAM: %s (fd=%d)", msg->filename, client_fd);
                strncpy(current_username, msg->username, MAX_USERNAME - 1);
                
                // Stream file word by word
                ss_stream_file(ss, client_fd, msg->filename);
                keep_alive = false; // Close after STREAM
                break;
            }
            
            case MSG_UNDO_FILE: {
                FileOpMsg* msg = (FileOpMsg*)buffer;
                log_message("SS", "UNDO: %s (fd=%d)", msg->filename, client_fd);
                strncpy(current_username, msg->username, MAX_USERNAME - 1);
                
                int result = ss_undo_file(ss, msg->filename);
                resp.type = (result == 0) ? MSG_SUCCESS : MSG_ERROR;
                resp.length = 0;
                send(client_fd, &resp, sizeof(MessageHeader), 0);
                keep_alive = false;
                break;
            }
            
            default:
                log_error("SS", "Unknown message type: %d (fd=%d)", header.type, client_fd);
                keep_alive = false;
                break;
        }
    }
    
    // Clean up any locks held by this client
    if (current_username[0] != '\0') {
        log_message("SS", "Cleaning up locks for %s before closing connection (fd=%d)", current_username, client_fd);
        cleanup_client_locks(ss, current_username);
    }
    
    log_message("SS", "Closing client connection (fd=%d)", client_fd);
    close(client_fd);
    
    return NULL;
}

// Save undo state to disk
int ss_save_undo_state(StorageServer* ss, int undo_idx) {
    if (undo_idx < 0 || undo_idx >= 100 || !ss->undo_state[undo_idx].has_backup) {
        return -1;
    }
    
    char undo_path[MAX_PATH];
    snprintf(undo_path, MAX_PATH, "%s/.undo_%s.bak", 
             ss->storage_path, ss->undo_state[undo_idx].filename);
    
    FILE* fp = fopen(undo_path, "w");
    if (fp == NULL) {
        log_error("SS", "Failed to save undo state for %s", ss->undo_state[undo_idx].filename);
        return -1;
    }
    
    // Write filename and content
    fprintf(fp, "%s\n", ss->undo_state[undo_idx].filename);
    if (ss->undo_state[undo_idx].prev_content != NULL) {
        fprintf(fp, "%s", ss->undo_state[undo_idx].prev_content);
    }
    
    fclose(fp);
    log_message("SS", "Saved undo state for %s", ss->undo_state[undo_idx].filename);
    return 0;
}

// Load undo states from disk
int ss_load_undo_states(StorageServer* ss) {
    DIR* dir = opendir(ss->storage_path);
    if (dir == NULL) {
        return -1;
    }
    
    struct dirent* entry;
    int loaded = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strncmp(entry->d_name, ".undo_", 6) == 0) {
            // Extract filename from .undo_<filename>.bak
            char* dot = strrchr(entry->d_name, '.');
            if (dot == NULL || strcmp(dot, ".bak") != 0) continue;
            
            char filename[MAX_FILENAME];
            strncpy(filename, entry->d_name + 6, dot - entry->d_name - 6);
            filename[dot - entry->d_name - 6] = '\0';
            
            // Find empty slot
            int undo_idx = -1;
            for (int i = 0; i < 100; i++) {
                if (!ss->undo_state[i].has_backup) {
                    undo_idx = i;
                    break;
                }
            }
            
            if (undo_idx == -1) {
                log_error("SS", "No space for undo state, skipping %s", filename);
                continue;
            }
            
            // Read undo file
            char undo_path[MAX_PATH];
            snprintf(undo_path, MAX_PATH, "%s/%s", ss->storage_path, entry->d_name);
            
            FILE* fp = fopen(undo_path, "r");
            if (fp == NULL) continue;
            
            // Read filename (first line)
            char line[MAX_FILENAME + 1];
            if (fgets(line, sizeof(line), fp) == NULL) {
                fclose(fp);
                continue;
            }
            // Remove newline
            line[strcspn(line, "\n")] = '\0';
            
            // Read content
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fseek(fp, strlen(line) + 1, SEEK_SET);  // Skip first line + newline
            size -= ftell(fp);
            
            if (size > 0) {
                char* content = (char*)malloc(size + 1);
                if (content != NULL) {
                    size_t read_size = fread(content, 1, size, fp);
                    content[read_size] = '\0';
                    
                    strncpy(ss->undo_state[undo_idx].filename, filename, MAX_FILENAME - 1);
                    ss->undo_state[undo_idx].filename[MAX_FILENAME - 1] = '\0';
                    ss->undo_state[undo_idx].prev_content = content;
                    ss->undo_state[undo_idx].has_backup = true;
                    loaded++;
                }
            } else {
                strncpy(ss->undo_state[undo_idx].filename, filename, MAX_FILENAME - 1);
                ss->undo_state[undo_idx].filename[MAX_FILENAME - 1] = '\0';
                ss->undo_state[undo_idx].prev_content = NULL;
                ss->undo_state[undo_idx].has_backup = true;
                loaded++;
            }
            
            fclose(fp);
        }
    }
    
    closedir(dir);
    if (loaded > 0) {
        log_message("SS", "Loaded %d undo states from disk", loaded);
    }
    return 0;
}

// Save file metadata to disk
int ss_save_file_metadata(StorageServer* ss, const char* filename, SSFileMetadata* meta) {
    if (meta == NULL) return -1;
    
    char meta_path[MAX_PATH];
    snprintf(meta_path, MAX_PATH, "%s/.meta_%s", ss->storage_path, filename);
    
    FILE* fp = fopen(meta_path, "w");
    if (fp == NULL) {
        log_error("SS", "Failed to save metadata for %s", filename);
        return -1;
    }
    
    // Write metadata in a simple format
    fprintf(fp, "filename:%s\n", meta->filename);
    fprintf(fp, "owner:%s\n", meta->owner);
    fprintf(fp, "created:%ld\n", meta->created);
    fprintf(fp, "last_modified:%ld\n", meta->last_modified);
    fprintf(fp, "last_accessed:%ld\n", meta->last_accessed);
    fprintf(fp, "size:%zu\n", meta->size);
    fprintf(fp, "word_count:%d\n", meta->word_count);
    fprintf(fp, "char_count:%d\n", meta->char_count);
    fprintf(fp, "num_read_users:%d\n", meta->num_read_users);
    fprintf(fp, "num_write_users:%d\n", meta->num_write_users);
    
    // Write read users
    for (int i = 0; i < meta->num_read_users; i++) {
        fprintf(fp, "read_user:%s\n", meta->read_users[i]);
    }
    
    // Write write users
    for (int i = 0; i < meta->num_write_users; i++) {
        fprintf(fp, "write_user:%s\n", meta->write_users[i]);
    }
    
    fclose(fp);
    return 0;
}

// Load file metadata from disk
int ss_load_file_metadata(StorageServer* ss) {
    DIR* dir = opendir(ss->storage_path);
    if (dir == NULL) {
        return -1;
    }
    
    struct dirent* entry;
    int loaded = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strncmp(entry->d_name, ".meta_", 6) == 0) {
            // Extract filename from .meta_<filename>
            char filename[MAX_FILENAME];
            strncpy(filename, entry->d_name + 6, MAX_FILENAME - 1);
            filename[MAX_FILENAME - 1] = '\0';
            
            char meta_path[MAX_PATH];
            snprintf(meta_path, MAX_PATH, "%s/%s", ss->storage_path, entry->d_name);
            
            FILE* fp = fopen(meta_path, "r");
            if (fp == NULL) continue;
            
            SSFileMetadata* meta = (SSFileMetadata*)malloc(sizeof(SSFileMetadata));
            if (meta == NULL) {
                fclose(fp);
                continue;
            }
            
            memset(meta, 0, sizeof(SSFileMetadata));
            meta->read_users = NULL;
            meta->write_users = NULL;
            meta->num_read_users = 0;
            meta->num_write_users = 0;
            
            char line[1024];
            while (fgets(line, sizeof(line), fp) != NULL) {
                line[strcspn(line, "\n")] = '\0';
                
                if (strncmp(line, "filename:", 9) == 0) {
                    strncpy(meta->filename, line + 9, MAX_FILENAME - 1);
                } else if (strncmp(line, "owner:", 6) == 0) {
                    strncpy(meta->owner, line + 6, MAX_USERNAME - 1);
                } else if (strncmp(line, "created:", 8) == 0) {
                    meta->created = atol(line + 8);
                } else if (strncmp(line, "last_modified:", 14) == 0) {
                    meta->last_modified = atol(line + 14);
                } else if (strncmp(line, "last_accessed:", 14) == 0) {
                    meta->last_accessed = atol(line + 14);
                } else if (strncmp(line, "size:", 5) == 0) {
                    meta->size = atol(line + 5);
                } else if (strncmp(line, "word_count:", 11) == 0) {
                    meta->word_count = atoi(line + 11);
                } else if (strncmp(line, "char_count:", 11) == 0) {
                    meta->char_count = atoi(line + 11);
                } else if (strncmp(line, "read_user:", 10) == 0) {
                    meta->read_users = (char**)realloc(meta->read_users, 
                                                       (meta->num_read_users + 1) * sizeof(char*));
                    meta->read_users[meta->num_read_users] = strdup(line + 10);
                    meta->num_read_users++;
                } else if (strncmp(line, "write_user:", 11) == 0) {
                    meta->write_users = (char**)realloc(meta->write_users, 
                                                        (meta->num_write_users + 1) * sizeof(char*));
                    meta->write_users[meta->num_write_users] = strdup(line + 11);
                    meta->num_write_users++;
                }
            }
            
            fclose(fp);
            
            // Add to metadata array
            pthread_mutex_lock(&ss->metadata_mutex);
            ss->file_metadata = (SSFileMetadata*)realloc(ss->file_metadata, 
                                                         (ss->num_metadata + 1) * sizeof(SSFileMetadata));
            // Copy metadata (pointers are already set correctly)
            ss->file_metadata[ss->num_metadata] = *meta;
            ss->num_metadata++;
            // Don't free meta - the pointers are now owned by the array entry
            // We'll free them when the metadata is deleted
            free(meta);
            pthread_mutex_unlock(&ss->metadata_mutex);
            
            loaded++;
        }
    }
    
    closedir(dir);
    if (loaded > 0) {
        log_message("SS", "Loaded %d file metadata entries from disk", loaded);
    }
    return 0;
}

// Get file metadata (caller must NOT hold metadata_mutex)
SSFileMetadata* ss_get_file_metadata(StorageServer* ss, const char* filename) {
    pthread_mutex_lock(&ss->metadata_mutex);
    
    for (int i = 0; i < ss->num_metadata; i++) {
        if (strcmp(ss->file_metadata[i].filename, filename) == 0) {
            SSFileMetadata* meta = &ss->file_metadata[i];
            pthread_mutex_unlock(&ss->metadata_mutex);
            return meta;
        }
    }
    
    pthread_mutex_unlock(&ss->metadata_mutex);
    return NULL;
}

// Update file metadata
int ss_update_file_metadata(StorageServer* ss, const char* filename, const char* owner, 
                            int word_count, int char_count, size_t size) {
    pthread_mutex_lock(&ss->metadata_mutex);
    
    SSFileMetadata* meta = NULL;
    for (int i = 0; i < ss->num_metadata; i++) {
        if (strcmp(ss->file_metadata[i].filename, filename) == 0) {
            meta = &ss->file_metadata[i];
            break;
        }
    }
    
    if (meta == NULL) {
        // Create new metadata entry
        ss->file_metadata = (SSFileMetadata*)realloc(ss->file_metadata, 
                                                     (ss->num_metadata + 1) * sizeof(SSFileMetadata));
        meta = &ss->file_metadata[ss->num_metadata];
        memset(meta, 0, sizeof(SSFileMetadata));
        
        strncpy(meta->filename, filename, MAX_FILENAME - 1);
        meta->filename[MAX_FILENAME - 1] = '\0';
        meta->created = time(NULL);
        meta->read_users = NULL;
        meta->write_users = NULL;
        meta->num_read_users = 0;
        meta->num_write_users = 0;
        
        ss->num_metadata++;
    }
    
    if (owner != NULL) {
        strncpy(meta->owner, owner, MAX_USERNAME - 1);
        meta->owner[MAX_USERNAME - 1] = '\0';
    }
    
    meta->last_modified = time(NULL);
    meta->last_accessed = time(NULL);
    meta->word_count = word_count;
    meta->char_count = char_count;
    meta->size = size;
    
    // Release lock before disk I/O to prevent deadlock
    pthread_mutex_unlock(&ss->metadata_mutex);
    
    // Save to disk (outside of lock to prevent blocking)
    int result = ss_save_file_metadata(ss, filename, meta);
    
    return result;
}

// ---------- History helpers ----------
// History stored as binary appended HistoryEntry structs in file: .hist_<filename>
int ss_append_history_entry(StorageServer* ss, const char* filename, HistoryEntry* entry) {
    if (ss == NULL || filename == NULL || entry == NULL) return -1;
    char hist_path[MAX_PATH];
    // Build history filename by stripping source extension and using .txt
    char hist_name[MAX_FILENAME];
    strncpy(hist_name, filename, MAX_FILENAME - 1);
    hist_name[MAX_FILENAME - 1] = '\0';
    char* last_slash = strrchr(hist_name, '/');
    char* ext = strrchr(hist_name, '.');
    if (ext != NULL && (last_slash == NULL || ext > last_slash)) {
        *ext = '\0';
    }
    snprintf(hist_path, MAX_PATH, "%s/.hist_%s.txt", ss->storage_path, hist_name);

    FILE* fp = fopen(hist_path, "ab");
    if (fp == NULL) {
        log_error("SS", "Failed to open history file %s for append", hist_path);
        return -1;
    }

    if (fwrite(entry, 1, sizeof(HistoryEntry), fp) != sizeof(HistoryEntry)) {
        log_error("SS", "Failed to write history entry for %s", filename);
        fclose(fp);
        return -1;
    }

    fflush(fp);
    int fd = fileno(fp);
    if (fd >= 0) fsync(fd);
    fclose(fp);
    // Ensure permissive access to history file as requested (0777)
    chmod(hist_path, 0777);
    return 0;
}

int ss_get_history_entries(StorageServer* ss, const char* filename, HistoryEntry** out_entries, int* out_count, int max_entries) {
    if (ss == NULL || filename == NULL || out_entries == NULL || out_count == NULL) return -1;
    *out_entries = NULL;
    *out_count = 0;

    char hist_path[MAX_PATH];
    // Build history filename by stripping source extension and using .txt
    char hist_name[MAX_FILENAME];
    strncpy(hist_name, filename, MAX_FILENAME - 1);
    hist_name[MAX_FILENAME - 1] = '\0';
    char* last_slash = strrchr(hist_name, '/');
    char* ext = strrchr(hist_name, '.');
    if (ext != NULL && (last_slash == NULL || ext > last_slash)) {
        *ext = '\0';
    }
    snprintf(hist_path, MAX_PATH, "%s/.hist_%s.txt", ss->storage_path, hist_name);

    FILE* fp = fopen(hist_path, "rb");
    if (fp == NULL) {
        // No history yet
        return 0;
    }

    // Get file size and number of entries
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size <= 0) { fclose(fp); return 0; }
    int total = size / sizeof(HistoryEntry);
    int to_read = total;
    if (max_entries > 0 && max_entries < to_read) to_read = max_entries;

    // Allocate array for last `to_read` entries
    HistoryEntry* entries = (HistoryEntry*)malloc(to_read * sizeof(HistoryEntry));
    if (entries == NULL) { fclose(fp); return -1; }

    // Seek to position of first entry we want
    long start_idx = total - to_read;
    fseek(fp, start_idx * sizeof(HistoryEntry), SEEK_SET);

    size_t read_count = fread(entries, sizeof(HistoryEntry), to_read, fp);
    fclose(fp);
    if ((int)read_count != to_read) {
        free(entries);
        return -1;
    }

    *out_entries = entries;
    *out_count = to_read;
    return 0;
}
