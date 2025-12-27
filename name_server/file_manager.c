#include "file_manager.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static unsigned int acl_hash_index(const char* username) {
    unsigned int hash = 2166136261u;
    const unsigned char* ptr = (const unsigned char*)username;
    while (*ptr) {
        hash ^= *ptr++;
        hash *= 16777619u;
    }
    return hash % ACL_HASH_BUCKETS;
}

static void acl_hash_init(ACLHashTable* table) {
    for (int i = 0; i < ACL_HASH_BUCKETS; i++) {
        table->buckets[i] = NULL;
    }
}

static bool acl_hash_contains(const ACLHashTable* table, const char* username) {
    unsigned int idx = acl_hash_index(username);
    ACLHashNode* node = table->buckets[idx];
    while (node != NULL) {
        if (strcmp(node->username, username) == 0) {
            return true;
        }
        node = node->next;
    }
    return false;
}

static void acl_hash_insert(ACLHashTable* table, const char* username) {
    unsigned int idx = acl_hash_index(username);
    ACLHashNode* node = table->buckets[idx];
    while (node != NULL) {
        if (strcmp(node->username, username) == 0) {
            return; // already present
        }
        node = node->next;
    }

    node = (ACLHashNode*)malloc(sizeof(ACLHashNode));
    if (node == NULL) {
        return;
    }
    strncpy(node->username, username, MAX_USERNAME - 1);
    node->username[MAX_USERNAME - 1] = '\0';
    node->next = table->buckets[idx];
    table->buckets[idx] = node;
}

static void acl_hash_remove(ACLHashTable* table, const char* username) {
    unsigned int idx = acl_hash_index(username);
    ACLHashNode* prev = NULL;
    ACLHashNode* node = table->buckets[idx];
    while (node != NULL) {
        if (strcmp(node->username, username) == 0) {
            if (prev == NULL) {
                table->buckets[idx] = node->next;
            } else {
                prev->next = node->next;
            }
            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}

static void acl_hash_clear(ACLHashTable* table) {
    for (int i = 0; i < ACL_HASH_BUCKETS; i++) {
        ACLHashNode* node = table->buckets[i];
        while (node != NULL) {
            ACLHashNode* next = node->next;
            free(node);
            node = next;
        }
        table->buckets[i] = NULL;
    }
}

static bool acl_list_contains_sorted(char** list, int count, const char* username) {
    int left = 0;
    int right = count - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        int cmp = strcmp(list[mid], username);
        if (cmp == 0) {
            return true;
        } else if (cmp < 0) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return false;
}

static int acl_list_find_insert_pos(char** list, int count, const char* username) {
    int left = 0;
    int right = count;
    while (left < right) {
        int mid = left + (right - left) / 2;
        if (strcmp(list[mid], username) < 0) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    return left;
}

static int acl_list_find_index(char** list, int count, const char* username) {
    int left = 0;
    int right = count - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        int cmp = strcmp(list[mid], username);
        if (cmp == 0) {
            return mid;
        } else if (cmp < 0) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return -1;
}

// Create Trie node
TrieNode* create_trie_node() {
    TrieNode* node = (TrieNode*)malloc(sizeof(TrieNode));
    if (node == NULL) return NULL;
    
    for (int i = 0; i < 256; i++) {
        node->children[i] = NULL;
    }
    node->file_meta = NULL;
    node->is_end = false;
    
    return node;
}

// Insert file into Trie
void insert_file(TrieNode* root, const char* filename, FileMetadata* meta) {
    if (root == NULL || filename == NULL) return;
    
    TrieNode* curr = root;
    for (int i = 0; filename[i] != '\0'; i++) {
        unsigned char c = (unsigned char)filename[i];
        if (curr->children[c] == NULL) {
            curr->children[c] = create_trie_node();
        }
        curr = curr->children[c];
    }
    
    curr->is_end = true;
    curr->file_meta = meta;
}

// Search file in Trie
FileMetadata* search_file(TrieNode* root, const char* filename) {
    if (root == NULL || filename == NULL) return NULL;
    
    TrieNode* curr = root;
    for (int i = 0; filename[i] != '\0'; i++) {
        unsigned char c = (unsigned char)filename[i];
        if (curr->children[c] == NULL) {
            return NULL;
        }
        curr = curr->children[c];
    }
    
    if (curr->is_end) {
        return curr->file_meta;
    }
    return NULL;
}

// Delete file from Trie
void delete_file_from_trie(TrieNode* root, const char* filename) {
    if (root == NULL || filename == NULL) return;
    
    // Simple implementation: just mark as not end
    TrieNode* curr = root;
    for (int i = 0; filename[i] != '\0'; i++) {
        unsigned char c = (unsigned char)filename[i];
        if (curr->children[c] == NULL) {
            return;
        }
        curr = curr->children[c];
    }
    
    curr->is_end = false;
    if (curr->file_meta != NULL) {
        // Destroy mutex and free ACL lists
        pthread_mutex_destroy(&curr->file_meta->meta_lock);
        acl_hash_clear(&curr->file_meta->read_index);
        acl_hash_clear(&curr->file_meta->write_index);
        if (curr->file_meta->read_users) free(curr->file_meta->read_users);
        if (curr->file_meta->write_users) free(curr->file_meta->write_users);
        free(curr->file_meta);
        curr->file_meta = NULL;
    }
}

// Collect all files from Trie (DFS traversal)
void collect_all_files(TrieNode* root, FileMetadata*** files, int* count, const char* prefix) {
    if (root == NULL) return;
    
    // If this is end of a file, add it
    if (root->is_end && root->file_meta != NULL) {
        if (prefix == NULL || strncmp(root->file_meta->filename, prefix, strlen(prefix)) == 0) {
            *files = (FileMetadata**)realloc(*files, (*count + 1) * sizeof(FileMetadata*));
            (*files)[*count] = root->file_meta;
            (*count)++;
        }
    }
    
    // Recursively traverse all children
    for (int i = 0; i < 256; i++) {
        if (root->children[i] != NULL) {
            collect_all_files(root->children[i], files, count, prefix);
        }
    }
}

// Create file metadata
FileMetadata* create_file_metadata(const char* filename, const char* owner) {
    FileMetadata* meta = (FileMetadata*)malloc(sizeof(FileMetadata));
    if (meta == NULL) return NULL;
    
    strncpy(meta->filename, filename, MAX_FILENAME);
    strncpy(meta->owner, owner, MAX_USERNAME);
    meta->created = time(NULL);
    meta->last_modified = time(NULL);
    meta->last_accessed = time(NULL);
    meta->size = 0;
    meta->word_count = 0;
    meta->char_count = 0;
    meta->is_folder = false;
    
    // Initialize access control
    meta->read_users = NULL;
    meta->num_read_users = 0;
    acl_hash_init(&meta->read_index);
    meta->write_users = NULL;
    meta->num_write_users = 0;
    acl_hash_init(&meta->write_index);
    meta->access_requests = NULL;
    meta->num_access_requests = 0;
    meta->primary_ss = NULL;
    meta->replica_ss = NULL;
    
    // Initialize metadata mutex
    pthread_mutex_init(&meta->meta_lock, NULL);

    return meta;
}

// Add access request (if not already present)
void add_access_request(FileMetadata* meta, const char* requester) {
    if (meta == NULL || requester == NULL) return;
    pthread_mutex_lock(&meta->meta_lock);
    // Owner's requests are meaningless
    if (strcmp(meta->owner, requester) == 0) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    // If already a reader/writer, no need to request
    if (acl_hash_contains(&meta->read_index, requester) ||
        acl_hash_contains(&meta->write_index, requester)) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }

    // Check duplicate requests
    for (int i = 0; i < meta->num_access_requests; i++) {
        if (strcmp(meta->access_requests[i], requester) == 0) {
            pthread_mutex_unlock(&meta->meta_lock);
            return;
        }
    }

    char** new_list = (char**)realloc(meta->access_requests, (meta->num_access_requests + 1) * sizeof(char*));
    if (new_list == NULL) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    meta->access_requests = new_list;
    meta->access_requests[meta->num_access_requests] = (char*)malloc(MAX_USERNAME);
    if (meta->access_requests[meta->num_access_requests] == NULL) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    strncpy(meta->access_requests[meta->num_access_requests], requester, MAX_USERNAME);
    meta->access_requests[meta->num_access_requests][MAX_USERNAME-1] = '\0';
    meta->num_access_requests++;
    pthread_mutex_unlock(&meta->meta_lock);
}

// List pending requests into provided buffer as newline-separated usernames
void list_access_requests_string(FileMetadata* meta, char* outbuf, size_t buflen) {
    if (meta == NULL || outbuf == NULL) return;
    pthread_mutex_lock(&meta->meta_lock);
    outbuf[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < meta->num_access_requests; i++) {
        const char* req = meta->access_requests[i];
        size_t need = strlen(req) + 2; // name + '\n' + '\0'
        if (used + need < buflen) {
            strncat(outbuf, req, buflen - used - 1);
            strncat(outbuf, "\n", buflen - used - 1);
            used = strlen(outbuf);
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&meta->meta_lock);
}

// Remove request entry (used after approval/denial)
void remove_access_request(FileMetadata* meta, const char* requester) {
    if (meta == NULL || requester == NULL) return;
    pthread_mutex_lock(&meta->meta_lock);
    for (int i = 0; i < meta->num_access_requests; i++) {
        if (strcmp(meta->access_requests[i], requester) == 0) {
            free(meta->access_requests[i]);
            for (int j = i; j < meta->num_access_requests - 1; j++)
                meta->access_requests[j] = meta->access_requests[j+1];
            meta->num_access_requests--;
            if (meta->num_access_requests > 0) {
                meta->access_requests = (char**)realloc(meta->access_requests, meta->num_access_requests * sizeof(char*));
            } else {
                free(meta->access_requests);
                meta->access_requests = NULL;
            }
            break;
        }
    }
    pthread_mutex_unlock(&meta->meta_lock);
}

// Create a folder entry in the trie. Returns false if folder already exists.
bool create_folder(TrieNode* root, const char* foldername, const char* owner) {
    if (root == NULL || foldername == NULL) return false;
    if (search_file(root, foldername) != NULL) return false; // already exists

    FileMetadata* meta = create_file_metadata(foldername, owner);
    if (meta == NULL) return false;
    meta->is_folder = true;
    insert_file(root, foldername, meta);
    return true;
}

// Move a file (or folder) within the trie from src to dst. Returns false on error.
bool move_file(TrieNode* root, const char* src, const char* dst) {
    if (root == NULL || src == NULL || dst == NULL) return false;
    // Destination must not already exist
    if (search_file(root, dst) != NULL) return false;

    // Locate source node
    TrieNode* curr = root;
    for (int i = 0; src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        if (curr->children[c] == NULL) {
            return false; // src not found
        }
        curr = curr->children[c];
    }
    if (!curr->is_end || curr->file_meta == NULL) return false;

    FileMetadata* meta = curr->file_meta;
    // Detach from source node without freeing metadata
    curr->is_end = false;
    curr->file_meta = NULL;

    // Update metadata filename and insert at destination
    strncpy(meta->filename, dst, MAX_FILENAME);
    insert_file(root, dst, meta);
    return true;
}

// Update access time
void update_file_access_time(FileMetadata* meta) {
    if (meta != NULL) {
        meta->last_accessed = time(NULL);
    }
}

// Check read access
bool check_read_access(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return false;
    bool result = false;
    pthread_mutex_lock(&meta->meta_lock);
    // Owner always has access
    if (strcmp(meta->owner, username) == 0) {
        result = true;
    } else if (acl_hash_contains(&meta->read_index, username) ||
               acl_hash_contains(&meta->write_index, username)) {
        result = true;
    } else if (acl_list_contains_sorted(meta->read_users, meta->num_read_users, username) ||
               acl_list_contains_sorted(meta->write_users, meta->num_write_users, username)) {
        result = true;
    }
    pthread_mutex_unlock(&meta->meta_lock);
    return result;
}

// Check write access
bool check_write_access(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return false;
    bool result = false;
    pthread_mutex_lock(&meta->meta_lock);
    if (strcmp(meta->owner, username) == 0) {
        result = true;
    } else if (acl_hash_contains(&meta->write_index, username)) {
        result = true;
    } else if (acl_list_contains_sorted(meta->write_users, meta->num_write_users, username)) {
        result = true;
    }
    pthread_mutex_unlock(&meta->meta_lock);
    return result;
}

// No-lock variants ---------------------------------------------------------
// These functions perform the same checks as the locked versions but do NOT
// acquire or release meta->meta_lock. They MUST only be called when the
// caller already holds the global file-index lock to prevent races with
// deletion/insertions. Use these to avoid acquiring meta_lock while holding
// the file-index lock (prevents lock-order inversion).
bool check_read_access_nolock(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return false;
    // Owner always has access
    if (strcmp(meta->owner, username) == 0) {
        return true;
    }

    if (acl_hash_contains(&meta->read_index, username) ||
        acl_hash_contains(&meta->write_index, username)) {
        return true;
    }

    return acl_list_contains_sorted(meta->read_users, meta->num_read_users, username) ||
           acl_list_contains_sorted(meta->write_users, meta->num_write_users, username);
}

bool check_write_access_nolock(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return false;
    if (strcmp(meta->owner, username) == 0) {
        return true;
    }
    if (acl_hash_contains(&meta->write_index, username)) {
        return true;
    }
    return acl_list_contains_sorted(meta->write_users, meta->num_write_users, username);
}

// Add read access
void add_read_access(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return;
    pthread_mutex_lock(&meta->meta_lock);
    // Owner always has access
    if (strcmp(meta->owner, username) == 0) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    // Check existing
    if (acl_hash_contains(&meta->read_index, username) ||
        acl_hash_contains(&meta->write_index, username) ||
        acl_list_contains_sorted(meta->read_users, meta->num_read_users, username) ||
        acl_list_contains_sorted(meta->write_users, meta->num_write_users, username)) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }

    char* new_entry = (char*)malloc(MAX_USERNAME);
    if (new_entry == NULL) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    // Add to read list
    char** new_read = (char**)realloc(meta->read_users, (meta->num_read_users + 1) * sizeof(char*));
    if (new_read == NULL) {
        free(new_entry);
        pthread_mutex_unlock(&meta->meta_lock);
        return; // allocation failed, leave state unchanged
    }
    meta->read_users = new_read;
    int insert_pos = acl_list_find_insert_pos(meta->read_users, meta->num_read_users, username);
    int tail = meta->num_read_users - insert_pos;
    if (tail > 0) {
        memmove(&meta->read_users[insert_pos + 1], &meta->read_users[insert_pos], tail * sizeof(char*));
    }
    meta->read_users[insert_pos] = new_entry;
    strncpy(new_entry, username, MAX_USERNAME - 1);
    new_entry[MAX_USERNAME - 1] = '\0';
    meta->num_read_users++;
    acl_hash_insert(&meta->read_index, username);
    pthread_mutex_unlock(&meta->meta_lock);
}

// Add write access
void add_write_access(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return;
    pthread_mutex_lock(&meta->meta_lock);
    // Owner always has access
    if (strcmp(meta->owner, username) == 0) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    // Check if already a writer
    if (acl_hash_contains(&meta->write_index, username)) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    if (acl_list_contains_sorted(meta->write_users, meta->num_write_users, username)) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    // Remove from read list if present
    int read_idx = acl_list_find_index(meta->read_users, meta->num_read_users, username);
    if (read_idx >= 0) {
        free(meta->read_users[read_idx]);
        int tail = meta->num_read_users - read_idx - 1;
        if (tail > 0) {
            memmove(&meta->read_users[read_idx], &meta->read_users[read_idx + 1], tail * sizeof(char*));
        }
        meta->num_read_users--;
        if (meta->num_read_users > 0) {
            char** resized = (char**)realloc(meta->read_users, meta->num_read_users * sizeof(char*));
            if (resized != NULL) {
                meta->read_users = resized;
            }
        } else {
            free(meta->read_users);
            meta->read_users = NULL;
        }
        acl_hash_remove(&meta->read_index, username);
    }

    // Add to write list
    char* new_entry = (char*)malloc(MAX_USERNAME);
    if (new_entry == NULL) {
        pthread_mutex_unlock(&meta->meta_lock);
        return;
    }
    char** new_write = (char**)realloc(meta->write_users, (meta->num_write_users + 1) * sizeof(char*));
    if (new_write == NULL) {
        free(new_entry);
        pthread_mutex_unlock(&meta->meta_lock);
        return; // allocation failed
    }
    meta->write_users = new_write;
    int insert_pos = acl_list_find_insert_pos(meta->write_users, meta->num_write_users, username);
    int tail = meta->num_write_users - insert_pos;
    if (tail > 0) {
        memmove(&meta->write_users[insert_pos + 1], &meta->write_users[insert_pos], tail * sizeof(char*));
    }
    meta->write_users[insert_pos] = new_entry;
    strncpy(new_entry, username, MAX_USERNAME - 1);
    new_entry[MAX_USERNAME - 1] = '\0';
    meta->num_write_users++;
    acl_hash_insert(&meta->write_index, username);
    pthread_mutex_unlock(&meta->meta_lock);
}

// Remove access
void remove_access(FileMetadata* meta, const char* username) {
    if (meta == NULL || username == NULL) return;
    pthread_mutex_lock(&meta->meta_lock);
    // remove from read list
    int read_idx = acl_list_find_index(meta->read_users, meta->num_read_users, username);
    if (read_idx >= 0) {
        free(meta->read_users[read_idx]);
        int tail = meta->num_read_users - read_idx - 1;
        if (tail > 0) {
            memmove(&meta->read_users[read_idx], &meta->read_users[read_idx + 1], tail * sizeof(char*));
        }
        meta->num_read_users--;
        if (meta->num_read_users > 0) {
            char** resized = (char**)realloc(meta->read_users, meta->num_read_users * sizeof(char*));
            if (resized != NULL) {
                meta->read_users = resized;
            }
        } else {
            free(meta->read_users);
            meta->read_users = NULL;
        }
        acl_hash_remove(&meta->read_index, username);
    }
    // remove from write list
    int write_idx = acl_list_find_index(meta->write_users, meta->num_write_users, username);
    if (write_idx >= 0) {
        free(meta->write_users[write_idx]);
        int tail = meta->num_write_users - write_idx - 1;
        if (tail > 0) {
            memmove(&meta->write_users[write_idx], &meta->write_users[write_idx + 1], tail * sizeof(char*));
        }
        meta->num_write_users--;
        if (meta->num_write_users > 0) {
            char** resized = (char**)realloc(meta->write_users, meta->num_write_users * sizeof(char*));
            if (resized != NULL) {
                meta->write_users = resized;
            }
        } else {
            free(meta->write_users);
            meta->write_users = NULL;
        }
        acl_hash_remove(&meta->write_index, username);
    }
    pthread_mutex_unlock(&meta->meta_lock);
}
