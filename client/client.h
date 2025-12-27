#ifndef CLIENT_H
#define CLIENT_H

#include "../common/protocol.h"

typedef struct {
    char username[MAX_USERNAME];
    char nm_ip[MAX_IP];
    uint16_t nm_port;
    int nm_sockfd;
} Client;

// Core functions
int client_init(Client* client, const char* username, const char* nm_ip, uint16_t nm_port);
void client_start(Client* client);
int client_register(Client* client);

// Command execution
int execute_command(Client* client, const char* command);

// Individual commands
void cmd_view(Client* client, const char* flags);
void cmd_read(Client* client, const char* filename);
void cmd_create(Client* client, const char* filename);
void cmd_write(Client* client, const char* filename, int sentence_num);
void cmd_delete(Client* client, const char* filename);
void cmd_info(Client* client, const char* filename);
void cmd_stream(Client* client, const char* filename);
void cmd_list(Client* client);
void cmd_add_access(Client* client, const char* flags, const char* filename, const char* username);
void cmd_rem_access(Client* client, const char* filename, const char* username);
void cmd_exec(Client* client, const char* filename);
void cmd_undo(Client* client, const char* filename);

// HISTORY command: HISTORY <filename> [max_entries]
void cmd_history(Client* client, const char* filename, int max_entries);

// Direct SS communication
int connect_to_ss(const char* ip, uint16_t port);
void stream_from_ss(int ss_fd, const char* filename);

#endif // CLIENT_H
