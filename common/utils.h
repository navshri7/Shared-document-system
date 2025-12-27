#ifndef UTILS_H
#define UTILS_H

#include <sys/time.h>
#include <time.h>
#include "protocol.h"

// Logging
void log_message(const char* component, const char* format, ...);
void log_error(const char* component, const char* format, ...);

// Network helpers
int send_message(int sockfd, MessageHeader* header, void* payload);
int recv_message(int sockfd, MessageHeader* header, void* payload, int max_size);
int create_tcp_socket();
int connect_to_server(const char* ip, uint16_t port);

// Reliable network operations with timeout and retry
#define DEFAULT_TIMEOUT_SEC 30   // 30 seconds - generous timeout for server recovery
#define MAX_RETRIES 3

int set_socket_timeout(int sockfd, int timeout_sec);
int send_with_retry(int sockfd, void* data, size_t len, int max_retries);
int recv_with_timeout(int sockfd, void* data, size_t len, int timeout_sec);
int send_message_reliable(int sockfd, MessageHeader* header, void* payload, int max_retries);
int recv_message_reliable(int sockfd, MessageHeader* header, void* payload, int max_size, int timeout_sec);

// Time utilities
char* get_timestamp();

// String utilities
void trim_whitespace(char* str);
int split_string(char* str, char delim, char** tokens, int max_tokens);

#endif // UTILS_H
