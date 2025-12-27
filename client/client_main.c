#include "client.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <nm_ip> <nm_port>\n", argv[0]);
        printf("Example: %s 127.0.0.1 8080\n", argv[0]);
        return 1;
    }
    
    const char* nm_ip = argv[1];
    uint16_t nm_port = (uint16_t)atoi(argv[2]);
    
    // Get username from user
    char username[MAX_USERNAME];
    printf("Enter your username: ");
    if (fgets(username, sizeof(username), stdin) == NULL) {
        printf("Failed to read username\n");
        return 1;
    }
    username[strcspn(username, "\n")] = 0;  // Remove newline
    
    Client client;
    
    // Initialize client
    if (client_init(&client, username, nm_ip, nm_port) < 0) {
        printf("Failed to initialize client\n");
        return 1;
    }
    
    // Register with Name Server
    if (client_register(&client) < 0) {
        printf("Failed to register with Name Server\n");
        return 1;
    }
    
    // Start interactive session
    client_start(&client);
    
    return 0;
}
