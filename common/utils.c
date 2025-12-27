#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

// Logging functions
void log_message(const char* component, const char* format, ...) {
    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    printf("[%s] [%s] ", timestamp, component);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
}

void log_error(const char* component, const char* format, ...) {
    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(stderr, "[%s] [%s] ERROR: ", timestamp, component);
    
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    
    fprintf(stderr, "\n");
    fflush(stderr);
}

// Network helpers
int send_message(int sockfd, MessageHeader* header, void* payload) {
    // Send header first
    ssize_t sent = send(sockfd, header, sizeof(MessageHeader), 0);
    if (sent != sizeof(MessageHeader)) {
        return -1;
    }
    
    // Send payload if exists
    if (header->length > 0 && payload != NULL) {
        sent = send(sockfd, payload, header->length, 0);
        if (sent != (ssize_t)header->length) {
            return -1;
        }
    }
    
    return 0;
}

int recv_message(int sockfd, MessageHeader* header, void* payload, int max_size) {
    // Receive header first
    ssize_t received = recv(sockfd, header, sizeof(MessageHeader), MSG_WAITALL);
    if (received != sizeof(MessageHeader)) {
        return -1;
    }
    
    // Receive payload if exists
    if (header->length > 0 && payload != NULL) {
        if (header->length > (uint32_t)max_size) {
            return -1;  // Payload too large
        }
        
        received = recv(sockfd, payload, header->length, MSG_WAITALL);
        if (received != (ssize_t)header->length) {
            return -1;
        }
    }
    
    return 0;
}

int create_tcp_socket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

int connect_to_server(const char* ip, uint16_t port) {
    int sockfd = create_tcp_socket();
    if (sockfd < 0) {
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Time utilities
char* get_timestamp() {
    static char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return timestamp;
}

// String utilities
void trim_whitespace(char* str) {
    if (str == NULL) return;
    
    // Trim leading spaces
    char* start = str;
    while (isspace((unsigned char)*start)) start++;
    
    // Trim trailing spaces
    char* end = str + strlen(str) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    
    // Move trimmed string to beginning
    size_t len = end - start + 1;
    memmove(str, start, len);
    str[len] = '\0';
}

int split_string(char* str, char delim, char** tokens, int max_tokens) {
    int count = 0;
    char* token = strtok(str, &delim);
    
    while (token != NULL && count < max_tokens) {
        tokens[count++] = token;
        token = strtok(NULL, &delim);
    }
    
    return count;
}

int set_nm_socket_timeout(int sockfd, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;

    // Set the SO_RCVTIMEO option for the socket
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) failed");
        return -1;
    }

    return 0;
}

// Set socket timeout (both send and receive)
int set_socket_timeout(int sockfd, int timeout_sec) {
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    
    // Set receive timeout
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_error("NET", "Failed to set SO_RCVTIMEO: %s", strerror(errno));
        return -1;
    }
    
    // Set send timeout
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        log_error("NET", "Failed to set SO_SNDTIMEO: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

// Send with retry on transient errors
int send_with_retry(int sockfd, void* data, size_t len, int max_retries) {
    int attempts = 0;
    
    while (attempts < max_retries) {
        // Use MSG_NOSIGNAL to prevent SIGPIPE on closed connections
        ssize_t sent = send(sockfd, data, len, MSG_NOSIGNAL);
        
        if (sent == (ssize_t)len) {
            return 0;  // Success
        }
        
        if (sent < 0) {
            // Check if it's a transient error
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                attempts++;
                log_message("NET", "Send retry %d/%d due to %s", attempts, max_retries, strerror(errno));
                usleep(100000);  // Wait 100ms before retry
                continue;
            } else {
                // Fatal error
                log_error("NET", "Send failed fatally: %s", strerror(errno));
                return -1;
            }
        } else {
            // Partial send - this shouldn't happen with TCP but handle it
            log_error("NET", "Partial send: %zd/%zu bytes", sent, len);
            return -1;
        }
    }
    
    log_error("NET", "Send failed after %d retries", max_retries);
    return -1;
}

// Receive with timeout
int recv_with_timeout(int sockfd, void* data, size_t len, int timeout_sec) {
    fd_set readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    int sel = select(sockfd + 1, &readfds, NULL, NULL, &tv);
    if (sel == 0) {
        log_error("NET", "Receive timeout after %d seconds", timeout_sec);
        return -1;
    }
    if (sel < 0) {
        log_error("NET", "Select failed: %s", strerror(errno));
        return -1;
    }

    ssize_t received = recv(sockfd, data, len, MSG_WAITALL);
    if (received == (ssize_t)len) {
        return 0;
    }

    if (received < 0) {
        log_error("NET", "Receive failed: %s", strerror(errno));
        return -1;
    } else if (received == 0) {
        log_error("NET", "Connection closed by peer");
        return -1;
    } else {
        log_error("NET", "Partial receive: %zd/%zu bytes", received, len);
        return -1;
    }
}

// Reliable message send with ACK expectation
int send_message_reliable(int sockfd, MessageHeader* header, void* payload, int max_retries) {
    int attempts = 0;
    
    while (attempts < max_retries) {
        // Send header
        if (send_with_retry(sockfd, header, sizeof(MessageHeader), max_retries) < 0) {
            attempts++;
            log_message("NET", "Header send failed, retry %d/%d", attempts, max_retries);
            if (attempts >= max_retries) return -1;
            usleep(200000);  // Wait 200ms
            continue;
        }
        
        // Send payload if exists
        if (header->length > 0 && payload != NULL) {
            if (send_with_retry(sockfd, payload, header->length, max_retries) < 0) {
                attempts++;
                log_message("NET", "Payload send failed, retry %d/%d", attempts, max_retries);
                if (attempts >= max_retries) return -1;
                usleep(200000);  // Wait 200ms
                continue;
            }
        }
        
        return 0;  // Success
    }
    
    return -1;
}

// Reliable message receive with timeout
int recv_message_reliable(int sockfd, MessageHeader* header, void* payload, int max_size, int timeout_sec) {
    // Receive header with timeout
    if (recv_with_timeout(sockfd, header, sizeof(MessageHeader), timeout_sec) < 0) {
        return -1;
    }
    
    // Receive payload if exists
    if (header->length > 0 && payload != NULL) {
        if (header->length > (uint32_t)max_size) {
            log_error("NET", "Payload too large: %d > %d", header->length, max_size);
            return -1;
        }
        
        if (recv_with_timeout(sockfd, payload, header->length, timeout_sec) < 0) {
            return -1;
        }
    }
    
    return 0;
}
