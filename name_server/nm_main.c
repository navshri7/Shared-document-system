#include "name_server.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

NameServer nm_global;

void signal_handler(int signum) {
    log_message("NM", "Shutting down...");
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        printf("Example: %s 8080\n", argv[0]);
        return 1;
    }
    
    uint16_t port = (uint16_t)atoi(argv[1]);
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize Name Server
    if (nm_init(&nm_global, port) < 0) {
        printf("Failed to initialize Name Server\n");
        return 1;
    }
    
    // Start server
    nm_start(&nm_global);
    
    return 0;
}
