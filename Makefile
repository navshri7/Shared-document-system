CC = gcc
CFLAGS = -Wall -Wextra -pthread -g
LDFLAGS = -pthread

# Directories
CLIENT_DIR = client
NM_DIR = name_server
SS_DIR = storage_server
COMMON_DIR = common

# Common object files
COMMON_OBJS = $(COMMON_DIR)/errors.o $(COMMON_DIR)/utils.o

# Client files
CLIENT_OBJS = $(CLIENT_DIR)/client.o $(CLIENT_DIR)/client_main.o
CLIENT_TARGET = client_app

# Name Server files
NM_OBJS = $(NM_DIR)/name_server.o $(NM_DIR)/file_manager.o $(NM_DIR)/access_control.o $(NM_DIR)/nm_main.o
NM_TARGET = nameserver

# Storage Server files
SS_OBJS = $(SS_DIR)/storage_server.o $(SS_DIR)/file_ops.o $(SS_DIR)/sentence_parser.o $(SS_DIR)/ss_main.o
SS_TARGET = storageserver

# Build all targets
all: $(CLIENT_TARGET) $(NM_TARGET) $(SS_TARGET)

# Client executable
$(CLIENT_TARGET): $(CLIENT_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Name Server executable
$(NM_TARGET): $(NM_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Storage Server executable
$(SS_TARGET): $(SS_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(CLIENT_OBJS) $(NM_OBJS) $(SS_OBJS) $(COMMON_OBJS)
	rm -f $(CLIENT_TARGET) $(NM_TARGET) $(SS_TARGET)
	rm -rf storage_ss_*

# Clean storage directories
clean-storage:
	rm -rf storage_ss_*

# Help target
help:
	@echo "Available targets:"
	@echo "  make all            - Build all components"
	@echo "  make client_app     - Build client only"
	@echo "  make nameserver     - Build name server only"
	@echo "  make storageserver  - Build storage server only"
	@echo "  make clean          - Remove build files"
	@echo "  make clean-storage  - Remove storage directories"
	@echo ""
	@echo "Usage examples:"
	@echo "  Terminal 1: ./nameserver 8080"
	@echo "  Terminal 2: ./storageserver 8080 9001"
	@echo "  Terminal 3: ./storageserver 8080 9002"
	@echo "  Terminal 4: ./client_app 127.0.0.1 8080"

.PHONY: all clean clean-storage help
