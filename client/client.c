#include "client.h"
#include "commands.h"
#include "../common/utils.h"
#include "../common/errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

// Initialize client
int client_init(Client* client, const char* username, const char* nm_ip, uint16_t nm_port) {
    if (client == NULL || username == NULL) return -1;
    
    // CRITICAL: Ignore SIGPIPE to prevent client from crashing when writing to closed socket
    // Without this, send() to a dead connection will terminate the process
    signal(SIGPIPE, SIG_IGN);
    
    strncpy(client->username, username, MAX_USERNAME);
    strncpy(client->nm_ip, nm_ip, MAX_IP);
    client->nm_port = nm_port;
    client->nm_sockfd = -1;
    
    log_message("CLIENT", "Client initialized for user: %s", username);
    return 0;
}

// Register with Name Server
int client_register(Client* client) {
    // Connect to Name Server
    client->nm_sockfd = connect_to_server(client->nm_ip, client->nm_port);
    if (client->nm_sockfd < 0) {
        log_error("CLIENT", "Failed to connect to Name Server at %s:%d", 
                 client->nm_ip, client->nm_port);
        return -1;
    }
    
    log_message("CLIENT", "Connected to Name Server");
    
    // Send registration message
    ClientRegisterMsg reg_msg;
    strncpy(reg_msg.username, client->username, MAX_USERNAME);
    strncpy(reg_msg.ip, "127.0.0.1", MAX_IP);
    reg_msg.nm_port = client->nm_port;
    reg_msg.ss_port = 0;  // Not used for client
    
    MessageHeader header;
    header.type = MSG_CLIENT_REGISTER;
    header.length = sizeof(ClientRegisterMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &reg_msg) < 0) {
        log_error("CLIENT", "Failed to send registration");
        close(client->nm_sockfd);
        return -1;
    }
    
    // Wait for response
    MessageHeader resp_header;
    log_message("CLIENT", "Waiting for registration response...");
    
    ssize_t received = recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL);
    if (received != sizeof(MessageHeader)) {
        log_error("CLIENT", "Failed to receive registration response (got %d bytes, expected %zu)", 
                 (int)received, sizeof(MessageHeader));
        if (received < 0) {
            perror("recv");
        }
        close(client->nm_sockfd);
        return -1;
    }
    
    log_message("CLIENT", "Received response type: %d", resp_header.type);
    
    if (resp_header.type == MSG_SUCCESS) {
        log_message("CLIENT", "Successfully registered with Name Server");
        return 0;
    } else {
        log_error("CLIENT", "Registration failed (response type: %d)", resp_header.type);
        close(client->nm_sockfd);
        return -1;
    }
}

// Start client interactive session
void client_start(Client* client) {
    printf("\n=== LangOS File System Client ===\n");
    printf("User: %s\n", client->username);
    printf("Type 'help' for available commands, 'quit' to exit\n\n");
    
    char command[1024];
    while (1) {
        printf("%s> ", client->username);
        fflush(stdout);
        
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        // Trim whitespace
        trim_whitespace(command);
        
        // Check for quit
        if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0) {
            printf("Goodbye!\n");
            break;
        }
        
        if (strcmp(command, "help") == 0) {
            printf("Available commands:\n");
            printf("  CREATE <filename>          - Create a new file\n");
            printf("  CREATEFOLDER <folder>      - Create a new folder (hierarchical)\n");
            printf("  READ <filename>            - Read file contents\n");
            printf("  WRITE <filename> <sent#>   - Edit sentence (interactive mode)\n");
            printf("  VIEW [flags]               - List files\n");
            printf("    -a                       - Show all files (regardless of access)\n");
            printf("    -l                       - Show detailed information\n");
            printf("    -al or -la               - Show all files with details\n");
            printf("  DELETE <filename>          - Delete a file\n");
            printf("  INFO <filename>            - Show file information\n");
            printf("  UNDO <filename>            - Revert last change to file\n");
            printf("  STREAM <filename>          - Stream file content word-by-word\n");
            printf("  CHECKPOINT <file> <tag>    - Create a checkpoint for a file\n");
            printf("  LISTCHECKPOINTS <file>     - List checkpoints for a file\n");
            printf("  VIEWCHECKPOINT <file> <tag>- View content of a checkpoint\n");
            printf("  LIST                       - List all users\n");
            printf("  ADDACCESS -R/-W <file> <user> - Add read/write access\n");
            printf("  REMACCESS <file> <user>    - Remove access\n");
            printf("  REQUESTACCESS <file>       - Request access to a file you don't own\n");
            printf("  LISTREQUESTS <file>        - (Owner) List pending access requests for a file\n");
            printf("  RESPONDREQUEST <file> <user> <APPROVE|DENY> [W] - (Owner) Approve/Deny request; optional W grants write when approving\n");
            printf("  EXEC <filename>            - Execute file as shell commands\n");
            printf("  MOVE <src> <dst>          - Move/Rename a file or folder\n");
            printf("  VIEWFOLDER <folder>       - View contents of a folder\n");
            printf("  HISTORY <filename>          - View file edit history (default max 10 entries)\n");
            printf("  REVERT <file> <tag>        - Revert file to a checkpoint\n");
            printf("  quit/exit                  - Exit client\n");
            continue;
        }
        
        if (strlen(command) == 0) {
            continue;
        }
        
        // Execute command
        execute_command(client, command);
    }
}

// Execute command
int execute_command(Client* client, const char* command) {
    char cmd[1024];
    strncpy(cmd, command, sizeof(cmd));
    
    // Parse command
    char* tokens[10];
    int num_tokens = split_string(cmd, ' ', tokens, 10);
    
    if (num_tokens == 0) return -1;
    
    // Route to appropriate handler
    if (strcmp(tokens[0], "CREATE") == 0) {
        if (num_tokens < 2) {
            printf("Usage: CREATE <filename>\n");
            return -1;
        }
        cmd_create(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "CREATEFOLDER") == 0) {
        if (num_tokens < 2) {
            printf("Usage: CREATEFOLDER <folder>\n");
            return -1;
        }
        cmd_create_folder(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "MOVE") == 0) {
        if (num_tokens < 3) {
            printf("Usage: MOVE <src> <dst>\n");
            return -1;
        }
        cmd_move(client, tokens[1], tokens[2]);
    }
    else if (strcmp(tokens[0], "VIEWFOLDER") == 0) {
        if (num_tokens < 2) {
            printf("Usage: VIEWFOLDER <folder>\n");
            return -1;
        }
        cmd_view_folder(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "CHECKPOINT") == 0) {
        if (num_tokens < 3) {
            printf("Usage: CHECKPOINT <filename> <tag>\n");
            return -1;
        }
        cmd_checkpoint(client, tokens[1], tokens[2]);
    }
    else if (strcmp(tokens[0], "LISTCHECKPOINTS") == 0) {
        if (num_tokens < 2) {
            printf("Usage: LISTCHECKPOINTS <filename>\n");
            return -1;
        }
        cmd_list_checkpoints(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "VIEWCHECKPOINT") == 0) {
        if (num_tokens < 3) {
            printf("Usage: VIEWCHECKPOINT <filename> <tag>\n");
            return -1;
        }
        cmd_view_checkpoint(client, tokens[1], tokens[2]);
    }
    else if (strcmp(tokens[0], "HISTORY") == 0) {
        if (num_tokens < 2) {
            printf("Usage: HISTORY <filename> [max_entries]\n");
            return -1;
        }
        int max_entries = 10;
        if (num_tokens >= 3) max_entries = atoi(tokens[2]);
        cmd_history(client, tokens[1], max_entries);
    }
    else if (strcmp(tokens[0], "REVERT") == 0) {
        if (num_tokens < 3) {
            printf("Usage: REVERT <filename> <tag>\n");
            return -1;
        }
        cmd_revert_checkpoint(client, tokens[1], tokens[2]);
    }
    else if (strcmp(tokens[0], "READ") == 0) {
        if (num_tokens < 2) {
            printf("Usage: READ <filename>\n");
            return -1;
        }
        cmd_read(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "VIEW") == 0) {
        const char* flags = (num_tokens > 1) ? tokens[1] : "";
        cmd_view(client, flags);
    }
    else if (strcmp(tokens[0], "DELETE") == 0) {
        if (num_tokens < 2) {
            printf("Usage: DELETE <filename>\n");
            return -1;
        }
        cmd_delete(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "INFO") == 0) {
        if (num_tokens < 2) {
            printf("Usage: INFO <filename>\n");
            return -1;
        }
        cmd_info(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "LIST") == 0) {
        cmd_list(client);
    }
    else if (strcmp(tokens[0], "WRITE") == 0) {
        if (num_tokens < 3) {
            printf("Usage: WRITE <filename> <sentence_number>\n");
            return -1;
        }
        int sentence_num = atoi(tokens[2]);
        cmd_write(client, tokens[1], sentence_num);
    }
    else if (strcmp(tokens[0], "UNDO") == 0) {
        if (num_tokens < 2) {
            printf("Usage: UNDO <filename>\n");
            return -1;
        }
        cmd_undo(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "STREAM") == 0) {
        if (num_tokens < 2) {
            printf("Usage: STREAM <filename>\n");
            return -1;
        }
        cmd_stream(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "ADDACCESS") == 0) {
        if (num_tokens < 4) {
            printf("Usage: ADDACCESS -R/-W <filename> <username>\n");
            return -1;
        }
        cmd_add_access(client, tokens[1], tokens[2], tokens[3]);
    }
    else if (strcmp(tokens[0], "REMACCESS") == 0) {
        if (num_tokens < 3) {
            printf("Usage: REMACCESS <filename> <username>\n");
            return -1;
        }
        cmd_rem_access(client, tokens[1], tokens[2]);
    }
    else if (strcmp(tokens[0], "EXEC") == 0) {
        if (num_tokens < 2) {
            printf("Usage: EXEC <filename>\n");
            return -1;
        }
        cmd_exec(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "REQUESTACCESS") == 0) {
        if (num_tokens < 2) {
            printf("Usage: REQUESTACCESS <filename>\n");
            return -1;
        }
        cmd_request_access(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "LISTREQUESTS") == 0) {
        if (num_tokens < 2) {
            printf("Usage: LISTREQUESTS <filename>\n");
            return -1;
        }
        cmd_list_requests(client, tokens[1]);
    }
    else if (strcmp(tokens[0], "RESPONDREQUEST") == 0) {
        if (num_tokens < 4) {
            printf("Usage: RESPONDREQUEST <filename> <requester> <APPROVE|DENY> [W]\n");
            return -1;
        }
        bool grant_write = false;
        if (num_tokens >= 5 && strcmp(tokens[4], "W") == 0) grant_write = true;
        cmd_respond_request(client, tokens[1], tokens[2], tokens[3], grant_write);
    }
    else {
        printf("Unknown command: %s\n", tokens[0]);
        printf("Type 'help' for available commands\n");
    }
    
    return 0;
}

// CREATEFOLDER command
void cmd_create_folder(Client* client, const char* foldername) {
    CreateFolderMsg msg;
    strncpy(msg.foldername, foldername, MAX_PATH);
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_CREATE_FOLDER;
    header.length = sizeof(CreateFolderMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send CREATEFOLDER request\n");
        return;
    }

    MessageHeader resp;
    if (recv(client->nm_sockfd, &resp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (resp.type == MSG_SUCCESS) {
        printf("Folder '%s' created successfully!\n", foldername);
    } else {
        ErrorMsg err;
        if (resp.length > 0 && recv(client->nm_sockfd, &err, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to create folder\n");
        }
    }
}

// MOVE command: MOVE <src> <dst>
void cmd_move(Client* client, const char* src, const char* dst) {
    MoveFileMsg msg;
    strncpy(msg.src, src, MAX_PATH);
    strncpy(msg.dst, dst, MAX_PATH);
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_MOVE_FILE;
    header.length = sizeof(MoveFileMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send MOVE request\n");
        return;
    }

    MessageHeader resp;
    if (recv(client->nm_sockfd, &resp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (resp.type == MSG_SUCCESS) {
        printf("Moved '%s' -> '%s' successfully\n", src, dst);
    } else {
        ErrorMsg err;
        if (resp.length > 0 && recv(client->nm_sockfd, &err, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to move file\n");
        }
    }
}

// VIEWFOLDER command
void cmd_view_folder(Client* client, const char* foldername) {
    ViewFolderMsg msg;
    strncpy(msg.foldername, foldername, MAX_PATH);
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_VIEW_FOLDER;
    header.length = sizeof(ViewFolderMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send VIEWFOLDER request\n");
        return;
    }

    MessageHeader resp;
    if (recv(client->nm_sockfd, &resp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (resp.type == MSG_ERROR) {
        ErrorMsg err;
        if (resp.length > 0 && recv(client->nm_sockfd, &err, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to view folder\n");
        }
        return;
    }

    int num_files = resp.length / sizeof(FileInfo);
    if (num_files == 0) {
        printf("No files found in folder '%s'\n", foldername);
        return;
    }

    FileInfo* files = (FileInfo*)malloc(resp.length);
    if (recv(client->nm_sockfd, files, resp.length, MSG_WAITALL) != (ssize_t)resp.length) {
        printf("ERROR: Failed to receive folder listing\n");
        free(files);
        return;
    }

    for (int i = 0; i < num_files; i++) {
        printf("--> %s\n", files[i].filename);
    }
    free(files);
}

// CHECKPOINT command: CHECKPOINT <filename> <tag>
void cmd_checkpoint(Client* client, const char* filename, const char* tag) {
    CheckpointMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.tag, tag, sizeof(msg.tag));
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_CREATE_CHECKPOINT;
    header.length = sizeof(CheckpointMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send CHECKPOINT request\n");
        return;
    }

    MessageHeader resp;
    if (recv_with_timeout(client->nm_sockfd, &resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
        printf("ERROR: No response from Name Server (timeout)\n");
        return;
    }

    if (resp.type == MSG_SUCCESS) {
        // consume any payload safely
        if (resp.length > 0) {
            char* tmp = (char*)malloc(resp.length);
            if (recv_with_timeout(client->nm_sockfd, tmp, resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
                printf("ERROR: Connection error receiving success payload\n");
                free(tmp);
                return;
            }
            free(tmp);
        }
        printf("Checkpoint '%s' created for %s\n", tag, filename);
    } else {
        ErrorMsg err;
        if (resp.length > 0 && recv_with_timeout(client->nm_sockfd, &err, sizeof(ErrorMsg), DEFAULT_TIMEOUT_SEC) == 0) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to create checkpoint\n");
        }
    }
}

// VIEWCHECKPOINTS <filename>
void cmd_view_checkpoints(Client* client, const char* filename) {
    CheckpointListReq msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_LIST_CHECKPOINTS;
    header.length = sizeof(CheckpointListReq);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send VIEWCHECKPOINTS request\n");
        return;
    }

    MessageHeader resp;
    if (recv_with_timeout(client->nm_sockfd, &resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
        printf("ERROR: No response from Name Server (timeout)\n");
        return;
    }

    if (resp.type == MSG_SUCCESS && resp.length > 0) {
        char* buf = (char*)malloc(resp.length);
        if (recv_with_timeout(client->nm_sockfd, buf, resp.length, DEFAULT_TIMEOUT_SEC) == 0) {
            printf("Checkpoints for %s:\n%s\n", filename, buf[0] ? buf : "(none)");
        } else {
            printf("ERROR: Failed to receive checkpoint list\n");
        }
        free(buf);
    } else if (resp.type == MSG_ERROR) {
        ErrorMsg err;
        if (resp.length > 0 && recv_with_timeout(client->nm_sockfd, &err, sizeof(ErrorMsg), DEFAULT_TIMEOUT_SEC) == 0) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("No checkpoints\n");
        }
    } else {
        printf("No checkpoints\n");
    }
}

// LISTCHECKPOINTS wrapper (keeps old function name compat)
void cmd_list_checkpoints(Client* client, const char* filename) {
    cmd_view_checkpoints(client, filename);
}

// VIEWCHECKPOINT <filename> <tag> - fetches and prints checkpoint content
void cmd_view_checkpoint(Client* client, const char* filename, const char* tag) {
    CheckpointMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.tag, tag, sizeof(msg.tag));
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_VIEW_CHECKPOINT;
    header.length = sizeof(CheckpointMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send VIEWCHECKPOINT request\n");
        return;
    }

    MessageHeader resp;
    if (recv(client->nm_sockfd, &resp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (resp.type == MSG_SUCCESS && resp.length > 0) {
        char* buf = (char*)malloc(resp.length);
        if (recv(client->nm_sockfd, buf, resp.length, MSG_WAITALL) == (ssize_t)resp.length) {
            printf("--- Checkpoint %s:%s ---\n%s\n", filename, tag, buf[0] ? buf : "(empty)");
        } else {
            printf("ERROR: Failed to receive checkpoint content\n");
        }
        free(buf);
    } else if (resp.type == MSG_ERROR) {
        ErrorMsg err;
        if (resp.length > 0 && recv(client->nm_sockfd, &err, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to view checkpoint\n");
        }
    } else {
        printf("No checkpoint content\n");
    }
}

// REVERT <filename> <tag>
void cmd_revert_checkpoint(Client* client, const char* filename, const char* tag) {
    CheckpointMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.tag, tag, sizeof(msg.tag));
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_REVERT_CHECKPOINT;
    header.length = sizeof(CheckpointMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send REVERT request\n");
        return;
    }

    MessageHeader resp;
    if (recv_with_timeout(client->nm_sockfd, &resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
        printf("ERROR: No response from Name Server (timeout)\n");
        return;
    }

    if (resp.type == MSG_SUCCESS) {
        // Consume any payload if present
        if (resp.length > 0) {
            char* tmp = (char*)malloc(resp.length);
            if (recv_with_timeout(client->nm_sockfd, tmp, resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
                printf("ERROR: Connection error after revert\n");
                free(tmp);
                return;
            }
            free(tmp);
        }
        printf("Reverted %s to checkpoint '%s'\n", filename, tag);
    } else {
        ErrorMsg err;
        if (resp.length > 0 && recv_with_timeout(client->nm_sockfd, &err, sizeof(ErrorMsg), DEFAULT_TIMEOUT_SEC) == 0) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to revert checkpoint\n");
        }
    }
}



// CREATE command
void cmd_create(Client* client, const char* filename) {
    FileOpMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_CREATE_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send CREATE request\n");
        return;
    }
    
    // Wait for response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_SUCCESS) {
        printf("File '%s' created successfully!\n", filename);
    } else {
        printf("ERROR: Failed to create file '%s'\n", filename);
    }
}

// READ command
void cmd_read(Client* client, const char* filename) {
    FileOpMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_READ_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send READ request\n");
        return;
    }
    
    // Wait for response (redirect or error)
    MessageHeader resp_header;
    
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_REDIRECT) {
        // Receive redirect info
        RedirectMsg redirect;
        if (recv(client->nm_sockfd, &redirect, sizeof(RedirectMsg), MSG_WAITALL) 
            != sizeof(RedirectMsg)) {
            printf("ERROR: Failed to receive redirect info\n");
            return;
        }
        // Connect to Storage Server
        int ss_fd = connect_to_server(redirect.ss_ip, redirect.ss_port);
        if (ss_fd < 0) {
            printf("ERROR: Failed to connect to Storage Server\n");
            return;
        }
        
        // Set timeout on socket
        set_socket_timeout(ss_fd, DEFAULT_TIMEOUT_SEC);
        
        // Send READ request to SS with retry
        header.type = MSG_CLIENT_READ;
        header.length = sizeof(FileOpMsg);
        
        if (send_message_reliable(ss_fd, &header, &msg, MAX_RETRIES) < 0) {
            printf("ERROR: Failed to send READ request to Storage Server\n");
            close(ss_fd);
            return;
        }
        
        // Receive content with timeout
        MessageHeader ss_resp;
        if (recv_message_reliable(ss_fd, &ss_resp, NULL, 0, DEFAULT_TIMEOUT_SEC) == 0) {
            if (ss_resp.type == MSG_SUCCESS && ss_resp.length > 0) {
                char* content = (char*)malloc(ss_resp.length);
                if (recv_with_timeout(ss_fd, content, ss_resp.length, DEFAULT_TIMEOUT_SEC) == 0) {
                    printf("%s\n", content);
                } else {
                    printf("ERROR: Connection lost while reading file content\n");
                }
                free(content);
            } else {
                printf("ERROR: Failed to read file\n");
            }
        } else {
            printf("ERROR: Storage Server not responding\n");
        }
        
        close(ss_fd);
    } else if (resp_header.type == MSG_ERROR) {
        ErrorMsg error;
        if (resp_header.length > 0 && recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", error.message);
        } else {
            printf("ERROR: File not found or access denied\n");
        }
    }
}

// VIEW command implementation
void cmd_view(Client* client, const char* flags) {
    // Parse flags
    bool show_all = false;
    bool show_details = false;
    
    if (flags != NULL && strlen(flags) > 0) {
        if (strstr(flags, "-a") != NULL || strstr(flags, "a") != NULL) {
            show_all = true;
        }
        if (strstr(flags, "-l") != NULL || strstr(flags, "l") != NULL) {
            show_details = true;
        }
    }
    
    // Prepare VIEW message
    ViewMsg msg;
    strncpy(msg.username, client->username, MAX_USERNAME);
    msg.show_all = show_all;
    msg.show_details = show_details;
    
    // Send VIEW request
    MessageHeader header;
    header.type = MSG_VIEW_FILES;
    header.length = sizeof(ViewMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send VIEW request\n");
        return;
    }
    
    // Receive response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_ERROR) {
        ErrorMsg error;
        if (resp_header.length > 0 && recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", error.message);
        } else {
            printf("ERROR: Failed to retrieve file list\n");
        }
        return;
    }
    
    // Calculate number of files
    int num_files = resp_header.length / sizeof(FileInfo);
    
    if (num_files == 0) {
        printf("No files found\n");
        return;
    }
    
    // Receive file list
    FileInfo* files = (FileInfo*)malloc(resp_header.length);
    if (recv(client->nm_sockfd, files, resp_header.length, MSG_WAITALL) 
        != (ssize_t)resp_header.length) {
        printf("ERROR: Failed to receive file list\n");
        free(files);
        return;
    }
    
    // Display results
    if (show_details) {
        // Detailed view
        printf("-------------------------------------------------------------------\n");
        printf("| %-20s | %5s | %5s | %-16s | %-10s |\n", 
               "Filename", "Words", "Chars", "Last Access", "Owner");
        printf("|----------------------|-------|-------|------------------|------------|\n");
        
        for (int i = 0; i < num_files; i++) {
            printf("| %-20s | %5d | %5d | %-16s | %-10s |\n",
                   files[i].filename,
                   files[i].word_count,
                   files[i].char_count,
                   files[i].last_access,
                   files[i].owner);
        }
        printf("-------------------------------------------------------------------\n");
    } else {
        // Simple view
        for (int i = 0; i < num_files; i++) {
            printf("--> %s\n", files[i].filename);
        }
    }
    
    free(files);
}

void cmd_delete(Client* client, const char* filename) {
    FileOpMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_DELETE_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send DELETE request\n");
        return;
    }
    
    // Wait for response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_SUCCESS) {
        printf("File '%s' deleted successfully!\n", filename);
    } else {
        ErrorMsg error;
        if (resp_header.length > 0 && 
            recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", error.message);
        } else {
            printf("ERROR: Failed to delete file '%s'\n", filename);
        }
    }
}

void cmd_info(Client* client, const char* filename) {
    FileOpMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_INFO_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send INFO request\n");
        return;
    }
    
    // Wait for response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_SUCCESS && resp_header.length > 0) {
        // Receive file info
        char* info_buffer = (char*)malloc(resp_header.length);
        if (recv(client->nm_sockfd, info_buffer, resp_header.length, MSG_WAITALL) 
            == (ssize_t)resp_header.length) {
            printf("%s", info_buffer);
        } else {
            printf("ERROR: Failed to receive file information\n");
        }
        free(info_buffer);
    } else {
        ErrorMsg error;
        if (resp_header.length > 0 && 
            recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", error.message);
        } else {
            printf("ERROR: File not found or access denied\n");
        }
    }
}

void cmd_write(Client* client, const char* filename, int sentence_num) {
    // First, get redirect to SS from NM
    FileOpMsg req_msg;
    strncpy(req_msg.filename, filename, MAX_FILENAME);
    strncpy(req_msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_WRITE_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &req_msg) < 0) {
        printf("ERROR: Failed to send WRITE request\n");
        return;
    }
    
    // Wait for redirect
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type != MSG_REDIRECT) {
        // If server returned an error payload, consume and display it to keep the
        // socket in sync for subsequent messages.
        if (resp_header.type == MSG_ERROR && resp_header.length > 0) {
            ErrorMsg error;
            if (recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
                printf("ERROR: %s\n", error.message);
            } else {
                printf("ERROR: Access denied or file not found\n");
            }
        } else {
            printf("ERROR: Access denied or file not found\n");
        }
        return;
    }
    
    // Get SS address
    RedirectMsg redirect;
    if (recv(client->nm_sockfd, &redirect, sizeof(RedirectMsg), MSG_WAITALL) 
        != sizeof(RedirectMsg)) {
        printf("ERROR: Failed to receive redirect info\n");
        return;
    }
    
    // Connect to SS
    int ss_fd = connect_to_server(redirect.ss_ip, redirect.ss_port);
    if (ss_fd < 0) {
        printf("ERROR: Failed to connect to Storage Server\n");
        return;
    }
    
    // Send WRITE_START to lock sentence
    WriteStartMsg start_msg;
    strncpy(start_msg.filename, filename, MAX_FILENAME);
    strncpy(start_msg.username, client->username, MAX_USERNAME);
    start_msg.sentence_num = sentence_num;
    
    header.type = MSG_WRITE_START;
    header.length = sizeof(WriteStartMsg);
    header.seq_num = 0;
    
    // Set timeout on socket before any communication
    set_socket_timeout(ss_fd, DEFAULT_TIMEOUT_SEC);
    
    // Use reliable send/recv to prevent SIGPIPE and handle errors gracefully
    if (send_message_reliable(ss_fd, &header, &start_msg, MAX_RETRIES) < 0) {
        printf("ERROR: Failed to send WRITE_START - Storage Server unreachable\n");
        close(ss_fd);
        return;
    }
    
    // Wait for acknowledgment with timeout
    if (recv_message_reliable(ss_fd, &resp_header, NULL, 0, DEFAULT_TIMEOUT_SEC) < 0) {
        printf("ERROR: No response from Storage Server (connection lost)\n");
        close(ss_fd);
        return;
    }
    
    if (resp_header.type == MSG_ERROR) {
        printf("ERROR: Sentence is locked by another user or invalid sentence index\n");
        close(ss_fd);
        return;
    }
    
    printf("Write mode started. Enter word updates (word_index content). Type ETIRW to finish.\n");
    
    // Set timeout on socket to detect dead connections
    set_socket_timeout(ss_fd, DEFAULT_TIMEOUT_SEC);
    
    // Interactive loop for word updates
    char input[BUFFER_SIZE];
    bool connection_lost = false;
    bool user_finished = false;
    
    while (1) {
        printf("> ");
        fflush(stdout);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            user_finished = true;
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        trim_whitespace(input);
        
        // Check for ETIRW (end write)
        if (strcmp(input, "ETIRW") == 0) {
            user_finished = true;
            break;
        }
        
        // Parse word_index and content
        char input_copy[BUFFER_SIZE];
        strncpy(input_copy, input, BUFFER_SIZE);
        
        char* space_pos = strchr(input_copy, ' ');
        if (space_pos == NULL) {
            printf("ERROR: Invalid format. Use: <word_index> <content>\n");
            continue;
        }
        
        *space_pos = '\0';
        int word_index = atoi(input_copy);
        char* content = space_pos + 1;
        
        // Send WRITE_UPDATE with retry
        WriteUpdateMsg update_msg;
        strncpy(update_msg.filename, filename, MAX_FILENAME);
        update_msg.sentence_num = sentence_num;
        update_msg.word_index = word_index;
        strncpy(update_msg.content, content, MAX_CONTENT);
        
        header.type = MSG_WRITE_UPDATE;
        header.length = sizeof(WriteUpdateMsg);
        header.seq_num++;
        
        // Try to send with error detection
        if (send_message_reliable(ss_fd, &header, &update_msg, MAX_RETRIES) < 0) {
            printf("ERROR: Connection lost to Storage Server\n");
            connection_lost = true;
            break;
        }
        
        // Wait for acknowledgment with timeout
        if (recv_message_reliable(ss_fd, &resp_header, NULL, 0, DEFAULT_TIMEOUT_SEC) < 0) {
            printf("ERROR: Storage Server not responding (connection lost)\n");
            connection_lost = true;
            break;
        }
        
        if (resp_header.type == MSG_ERROR) {
            printf("ERROR: Invalid word index\n");
        }
    }
    
    // Only send WRITE_END if connection is still alive and user finished normally
    if (!connection_lost && user_finished) {
        WriteEndMsg end_msg;
        strncpy(end_msg.filename, filename, MAX_FILENAME);
        end_msg.sentence_num = sentence_num;
        
        header.type = MSG_WRITE_END;
        header.length = sizeof(WriteEndMsg);
        header.seq_num++;
        
        if (send_message_reliable(ss_fd, &header, &end_msg, MAX_RETRIES) < 0) {
            printf("ERROR: Failed to commit changes - connection lost\n");
            connection_lost = true;
        } else {
            // Wait for final acknowledgment
            if (recv_message_reliable(ss_fd, &resp_header, NULL, 0, DEFAULT_TIMEOUT_SEC) == 0) {
                if (resp_header.type == MSG_SUCCESS) {
                    printf("Write Successful!\n");
                } else {
                    printf("ERROR: Write failed\n");
                }
            } else {
                printf("ERROR: No response from server\n");
                connection_lost = true;
            }
        }
    } else if (connection_lost) {
        printf("\nWARNING: Changes not saved due to connection loss.\n");
        printf("The sentence lock will be automatically released after timeout.\n");
    }
    
    close(ss_fd);
}

void cmd_stream(Client* client, const char* filename) {
    // First, get redirect to SS from NM
    FileOpMsg req_msg;
    strncpy(req_msg.filename, filename, MAX_FILENAME);
    strncpy(req_msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_STREAM_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &req_msg) < 0) {
        printf("ERROR: Failed to send STREAM request\n");
        return;
    }
    
    // Wait for redirect
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type != MSG_REDIRECT) {
        printf("ERROR: Access denied or file not found\n");
        return;
    }
    
    // Get SS address
    RedirectMsg redirect;
    if (recv(client->nm_sockfd, &redirect, sizeof(RedirectMsg), MSG_WAITALL) 
        != sizeof(RedirectMsg)) {
        printf("ERROR: Failed to receive redirect info\n");
        return;
    }
    
    // Connect to SS
    int ss_fd = connect_to_server(redirect.ss_ip, redirect.ss_port);
    if (ss_fd < 0) {
        printf("ERROR: Failed to connect to Storage Server\n");
        return;
    }
    
    // Send STREAM request to SS
    header.type = MSG_CLIENT_STREAM;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send(ss_fd, &header, sizeof(MessageHeader), 0) <= 0 ||
        send(ss_fd, &req_msg, sizeof(FileOpMsg), 0) <= 0) {
        printf("ERROR: Failed to send STREAM request to Storage Server\n");
        close(ss_fd);
        return;
    }
    
    // Set timeout for streaming
    set_socket_timeout(ss_fd, DEFAULT_TIMEOUT_SEC);
    
    // Receive and display words one by one
    while (1) {
        MessageHeader word_header;
        
        // Use reliable receive with timeout
        if (recv_with_timeout(ss_fd, &word_header, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
            printf("\nERROR: Connection lost during streaming\n");
            break;
        }
        
        if (word_header.type == MSG_STOP) {
            printf("\n");
            break;
        }
        
        if (word_header.type == MSG_ERROR) {
            printf("\nERROR: Streaming failed\n");
            break;
        }
        
        if (word_header.type == MSG_SUCCESS && word_header.length > 0) {
            char* word = (char*)malloc(word_header.length);
            if (recv_with_timeout(ss_fd, word, word_header.length, DEFAULT_TIMEOUT_SEC) == 0) {
                printf("%s ", word);
                fflush(stdout);
                // Delay 0.1 seconds (100ms)
                usleep(100000);
            } else {
                printf("\nERROR: Connection lost during streaming\n");
                free(word);
                break;
            }
            free(word);
        }
    }
    
    close(ss_fd);
}

void cmd_list(Client* client) {
    MessageHeader header;
    header.type = MSG_LIST_USERS;
    header.length = 0;
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, NULL) < 0) {
        printf("ERROR: Failed to send LIST request\n");
        return;
    }
    
    // Wait for response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_SUCCESS && resp_header.length > 0) {
        char* response = (char*)malloc(resp_header.length);
        if (recv(client->nm_sockfd, response, resp_header.length, MSG_WAITALL) 
            == (ssize_t)resp_header.length) {
            printf("%s", response);
        } else {
            printf("ERROR: Failed to receive user list\n");
        }
        free(response);
    } else {
        printf("ERROR: Failed to retrieve user list\n");
    }
}

void cmd_add_access(Client* client, const char* flags, const char* filename, const char* username) {
    // Parse flags (-R or -W)
    bool read_access = false;
    bool write_access = false;
    
    if (strcmp(flags, "-R") == 0) {
        read_access = true;
    } else if (strcmp(flags, "-W") == 0) {
        write_access = true;
        read_access = true;  // Write implies read
    } else {
        printf("ERROR: Invalid flag. Use -R for read access or -W for write access\n");
        return;
    }
    
    AccessMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    strncpy(msg.target_user, username, MAX_USERNAME);
    msg.read_access = read_access;
    msg.write_access = write_access;
    
    MessageHeader header;
    header.type = MSG_ADD_ACCESS;
    header.length = sizeof(AccessMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send ADDACCESS request\n");
        return;
    }
    
    // Wait for response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_SUCCESS) {
        if (write_access) {
            printf("Write (and read) access granted to %s for file '%s'\n", username, filename);
        } else {
            printf("Read access granted to %s for file '%s'\n", username, filename);
        }
    } else {
        ErrorMsg error;
        if (resp_header.length > 0 && 
            recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", error.message);
        } else {
            printf("ERROR: Failed to add access\n");
        }
    }
}

void cmd_rem_access(Client* client, const char* filename, const char* username) {
    AccessMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    strncpy(msg.target_user, username, MAX_USERNAME);
    msg.read_access = false;
    msg.write_access = false;
    
    MessageHeader header;
    header.type = MSG_REM_ACCESS;
    header.length = sizeof(AccessMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send REMACCESS request\n");
        return;
    }
    
    // Wait for response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_SUCCESS) {
        printf("Access removed for %s from file '%s'\n", username, filename);
    } else {
        ErrorMsg error;
        if (resp_header.length > 0 && 
            recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", error.message);
        } else {
            printf("ERROR: Failed to remove access\n");
        }
    }
}

// Request access to a file (non-owner)
void cmd_request_access(Client* client, const char* filename) {
    RequestAccessMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_REQUEST_ACCESS;
    header.length = sizeof(RequestAccessMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send REQUESTACCESS request\n");
        return;
    }

    MessageHeader resp;
    if (recv(client->nm_sockfd, &resp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (resp.type == MSG_SUCCESS) {
        printf("Access request sent for '%s'\n", filename);
    } else {
        ErrorMsg err;
        if (resp.length > 0 && recv(client->nm_sockfd, &err, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Request failed\n");
        }
    }
}

// List pending requests for a file (owner only)
void cmd_list_requests(Client* client, const char* filename) {
    AccessListReq msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);

    MessageHeader header;
    header.type = MSG_LIST_ACCESS_REQUESTS;
    header.length = sizeof(AccessListReq);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send LISTREQUESTS request\n");
        return;
    }

    MessageHeader resp;
    if (recv(client->nm_sockfd, &resp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (resp.type == MSG_SUCCESS && resp.length > 0) {
        char* buf = (char*)malloc(resp.length);
        if (recv(client->nm_sockfd, buf, resp.length, MSG_WAITALL) == (ssize_t)resp.length) {
            printf("Pending requests for %s:\n%s\n", filename, buf[0] ? buf : "(none)");
        } else {
            printf("ERROR: Failed to receive request list\n");
        }
        free(buf);
    } else if (resp.type == MSG_ERROR) {
        ErrorMsg err;
        if (resp.length > 0 && recv(client->nm_sockfd, &err, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to list requests\n");
        }
    } else {
        printf("No pending requests\n");
    }
}

// Respond to an access request (owner action)
void cmd_respond_request(Client* client, const char* filename, const char* requester, const char* action, bool grant_write) {
    AccessResponseMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    strncpy(msg.target_user, requester, MAX_USERNAME);
    msg.approve = (strcmp(action, "APPROVE") == 0);
    msg.grant_write = grant_write;

    MessageHeader header;
    header.type = MSG_RESPOND_ACCESS_REQUEST;
    header.length = sizeof(AccessResponseMsg);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send RESPONDREQUEST\n");
        return;
    }

    MessageHeader resp;
    if (recv(client->nm_sockfd, &resp, sizeof(MessageHeader), MSG_WAITALL) != sizeof(MessageHeader)) {
        printf("ERROR: No response from Name Server\n");
        return;
    }

    if (resp.type == MSG_SUCCESS) {
        if (msg.approve) {
            if (msg.grant_write) printf("Approved request: %s granted WRITE access to '%s'\n", requester, filename);
            else printf("Approved request: %s granted READ access to '%s'\n", requester, filename);
        } else {
            printf("Denied access request by %s for '%s'\n", requester, filename);
        }
    } else {
        ErrorMsg err;
        if (resp.length > 0 && recv(client->nm_sockfd, &err, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to respond to request\n");
        }
    }
}

void cmd_exec(Client* client, const char* filename) {
    FileOpMsg msg;
    strncpy(msg.filename, filename, MAX_FILENAME);
    strncpy(msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_EXEC_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &msg) < 0) {
        printf("ERROR: Failed to send EXEC request\n");
        return;
    }
    
    // Wait for response
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type == MSG_SUCCESS && resp_header.length > 0) {
        char* output = (char*)malloc(resp_header.length);
        if (recv(client->nm_sockfd, output, resp_header.length, MSG_WAITALL) 
            == (ssize_t)resp_header.length) {
            printf("%s", output);
        } else {
            printf("ERROR: Failed to receive execution output\n");
        }
        free(output);
    } else {
        ErrorMsg error;
        if (resp_header.length > 0 && 
            recv(client->nm_sockfd, &error, sizeof(ErrorMsg), MSG_WAITALL) == sizeof(ErrorMsg)) {
            printf("ERROR: %s\n", error.message);
        } else {
            printf("ERROR: Execution failed\n");
        }
    }
}

void cmd_undo(Client* client, const char* filename) {
    // First, get redirect to SS from NM
    FileOpMsg req_msg;
    strncpy(req_msg.filename, filename, MAX_FILENAME);
    strncpy(req_msg.username, client->username, MAX_USERNAME);
    
    MessageHeader header;
    header.type = MSG_UNDO_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    if (send_message(client->nm_sockfd, &header, &req_msg) < 0) {
        printf("ERROR: Failed to send UNDO request\n");
        return;
    }
    
    // Wait for redirect
    MessageHeader resp_header;
    if (recv(client->nm_sockfd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) 
        != sizeof(MessageHeader)) {
        printf("ERROR: Failed to receive response\n");
        return;
    }
    
    if (resp_header.type != MSG_REDIRECT) {
        printf("ERROR: Access denied or file not found\n");
        return;
    }
    
    // Get SS address
    RedirectMsg redirect;
    if (recv(client->nm_sockfd, &redirect, sizeof(RedirectMsg), MSG_WAITALL) 
        != sizeof(RedirectMsg)) {
        printf("ERROR: Failed to receive redirect info\n");
        return;
    }
    
    // Connect to SS
    int ss_fd = connect_to_server(redirect.ss_ip, redirect.ss_port);
    if (ss_fd < 0) {
        printf("ERROR: Failed to connect to Storage Server\n");
        return;
    }
    
    // Send UNDO request to SS
    header.type = MSG_UNDO_FILE;
    header.length = sizeof(FileOpMsg);
    header.seq_num = 0;
    
    send(ss_fd, &header, sizeof(MessageHeader), 0);
    send(ss_fd, &req_msg, sizeof(FileOpMsg), 0);
    
    // Wait for acknowledgment
    if (recv(ss_fd, &resp_header, sizeof(MessageHeader), MSG_WAITALL) == sizeof(MessageHeader)) {
        if (resp_header.type == MSG_SUCCESS) {
            printf("Undo Successful for file '%s'!\n", filename);
        } else {
            printf("ERROR: Undo operation failed for file '%s'\n", filename);
        }
    } else {
        printf("ERROR: Failed to receive UNDO response\n");
    }
    
    close(ss_fd);
}


// HISTORY <filename> [max_entries]
void cmd_history(Client* client, const char* filename, int max_entries) {
    HistoryReq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.filename, filename, MAX_FILENAME);
    strncpy(req.username, client->username, MAX_USERNAME);
    req.max_entries = max_entries;

    MessageHeader header;
    header.type = MSG_HISTORY_REQUEST;
    header.length = sizeof(HistoryReq);
    header.seq_num = 0;

    if (send_message(client->nm_sockfd, &header, &req) < 0) {
        printf("ERROR: Failed to send HISTORY request\n");
        return;
    }

    MessageHeader resp;
    if (recv_with_timeout(client->nm_sockfd, &resp, sizeof(MessageHeader), DEFAULT_TIMEOUT_SEC) < 0) {
        printf("ERROR: No response from Name Server (timeout)\n");
        return;
    }

    if (resp.type == MSG_HISTORY_RESPONSE && resp.length > 0) {
        char* buf = (char*)malloc(resp.length);
        if (buf == NULL) {
            printf("ERROR: Out of memory\n");
            return;
        }
        if (recv_with_timeout(client->nm_sockfd, buf, resp.length, DEFAULT_TIMEOUT_SEC) < 0) {
            printf("ERROR: Failed to receive HISTORY payload\n");
            free(buf);
            return;
        }

        if (resp.length < (int)sizeof(HistoryResp)) {
            printf("ERROR: Malformed HISTORY response\n");
            free(buf);
            return;
        }

        HistoryResp* hresp = (HistoryResp*)buf;
        int entries = hresp->entries_count;
        size_t expected = sizeof(HistoryResp) + (size_t)entries * sizeof(HistoryEntry);
        if ((size_t)resp.length < expected) {
            printf("ERROR: Incomplete HISTORY entries (expected %zu bytes, got %u)\n", expected, resp.length);
            free(buf);
            return;
        }

        HistoryEntry* entries_arr = (HistoryEntry*)(buf + sizeof(HistoryResp));

        printf("History for %s (last %d entries):\n", filename, entries);
        for (int i = 0; i < entries; i++) {
            HistoryEntry* e = &entries_arr[i];
            printf("%2d) [%s] %s by %s\n", i + 1, e->timestamp, e->op_type, e->username);
            printf("Chars: +%d/-%d\n", e->chars_added, e->chars_removed);
            if (e->comment[0]) printf("     Comment: %s\n", e->comment);
        }

        free(buf);
    } else if (resp.type == MSG_ERROR) {
        ErrorMsg err;
        if (resp.length > 0 && recv_with_timeout(client->nm_sockfd, &err, sizeof(ErrorMsg), DEFAULT_TIMEOUT_SEC) == 0) {
            printf("ERROR: %s\n", err.message);
        } else {
            printf("ERROR: Failed to fetch history or access denied\n");
        }
    } else {
        printf("No history available for %s\n", filename);
    }
}

