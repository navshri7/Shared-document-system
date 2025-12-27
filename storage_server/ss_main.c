#include "storage_server.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <nm_port> <client_port>\n", argv[0]);
        printf("Example: %s 8080 9001\n", argv[0]);
        return 1;
    }
    
    uint16_t nm_port = (uint16_t)atoi(argv[1]);
    uint16_t client_port = (uint16_t)atoi(argv[2]);
    
    StorageServer ss;
    
    // Initialize
    if (ss_init(&ss, "127.0.0.1", nm_port, client_port) < 0) {
        printf("Failed to initialize Storage Server\n");
        return 1;
    }
    
    // Register with Name Server
    if (ss_register_with_nm(&ss) < 0) {
        printf("Failed to register with Name Server\n");
        return 1;
    }
    
    // Start server
    ss_start(&ss);
    
    return 0;
}
