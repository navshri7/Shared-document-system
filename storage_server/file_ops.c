#include "file_ops.h"
#include "storage_server.h"
#include "sentence_parser.h"
#include "../common/utils.h"
#include "../common/errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

// Helper: Get full file path
static void get_file_path(StorageServer* ss, const char* filename, char* path_buf) {
    snprintf(path_buf, MAX_PATH, "%s/%s", ss->storage_path, filename);
}

// Helper: Get swap file path for a user's write session
static void get_swap_file_path(StorageServer* ss, const char* filename, 
                               int sentence_num, char* path_buf) {
    snprintf(path_buf, MAX_PATH, "%s/.swap_%s_s%d", 
             ss->storage_path, filename, sentence_num);
}

// Helper: Get or create per-file commit mutex
static pthread_mutex_t* get_file_commit_mutex(StorageServer* ss, const char* filename) {
    pthread_mutex_lock(&ss->file_commit_mutexes_mutex);
    
    // Look for existing mutex for this file
    for (int i = 0; i < ss->num_file_commit_mutexes; i++) {
        if (ss->file_commit_mutexes[i].in_use && 
            strcmp(ss->file_commit_mutexes[i].filename, filename) == 0) {
            pthread_mutex_t* result = &ss->file_commit_mutexes[i].mutex;
            pthread_mutex_unlock(&ss->file_commit_mutexes_mutex);
            return result;
        }
    }
    
    // Find empty slot or allocate new one
    int idx = -1;
    for (int i = 0; i < ss->num_file_commit_mutexes; i++) {
        if (!ss->file_commit_mutexes[i].in_use) {
            idx = i;
            break;
        }
    }
    
    if (idx == -1) {
        ss->file_commit_mutexes = (FileCommitMutex*)realloc(
            ss->file_commit_mutexes, 
            (ss->num_file_commit_mutexes + 1) * sizeof(FileCommitMutex));
        idx = ss->num_file_commit_mutexes;
        ss->num_file_commit_mutexes++;
        pthread_mutex_init(&ss->file_commit_mutexes[idx].mutex, NULL);
    }
    
    // Initialize the mutex entry
    strncpy(ss->file_commit_mutexes[idx].filename, filename, MAX_FILENAME - 1);
    ss->file_commit_mutexes[idx].filename[MAX_FILENAME - 1] = '\0';
    ss->file_commit_mutexes[idx].in_use = true;
    
    pthread_mutex_t* result = &ss->file_commit_mutexes[idx].mutex;
    pthread_mutex_unlock(&ss->file_commit_mutexes_mutex);
    return result;
}

// Internal read function - NO lock checking (for direct file access)
static int ss_read_file_internal(StorageServer* ss, const char* filename, char** content) {
    char filepath[MAX_PATH];
    get_file_path(ss, filename, filepath);

    if (access(filepath, F_OK) != 0) {
        log_error("SS", "File %s not found", filename);
        return ERR_FILE_NOT_FOUND;
    }
    
    FILE* fp = fopen(filepath, "r");
    if (fp == NULL) {
        log_error("SS", "Failed to open file %s", filename);
        return ERR_INTERNAL;
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    *content = (char*)malloc(size + 1);
    if (*content == NULL) {
        fclose(fp);
        return ERR_INTERNAL;
    }
    
    size_t read_size = fread(*content, 1, size, fp);
    (*content)[read_size] = '\0';
    fclose(fp);
    
    return ERR_SUCCESS;
}

// Create a new file
int ss_create_file(StorageServer* ss, const char* filename) {
    char filepath[MAX_PATH];
    get_file_path(ss, filename, filepath);
    
    if (access(filepath, F_OK) == 0) {
        log_error("SS", "File %s already exists", filename);
        return ERR_FILE_EXISTS;
    }
    
    FILE* fp = fopen(filepath, "w");
    if (fp == NULL) {
        log_error("SS", "Failed to create file %s", filename);
        return ERR_INTERNAL;
    }
    fclose(fp);
    
    log_message("SS", "Created file: %s", filename);
    return ERR_SUCCESS;
}

// Read file content - Simple and safe (readers just read, no locking needed)
int ss_read_file(StorageServer* ss, const char* filename, char** content) {
    char filepath[MAX_PATH];
    get_file_path(ss, filename, filepath);

    if (access(filepath, F_OK) != 0) {
        log_error("SS", "File %s not found", filename);
        return ERR_FILE_NOT_FOUND;
    }

    // Simple read - atomic at filesystem level due to rename() in write_end
    FILE* fp = fopen(filepath, "r");
    if (fp == NULL) {
        log_error("SS", "Failed to open file %s", filename);
        return ERR_INTERNAL;
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    *content = (char*)malloc(size + 1);
    if (*content == NULL) {
        fclose(fp);
        return ERR_INTERNAL;
    }
    
    size_t read_size = fread(*content, 1, size, fp);
    (*content)[read_size] = '\0';
    fclose(fp);
    
    // Update metadata
    SSFileMetadata* meta = ss_get_file_metadata(ss, filename);
    if (meta != NULL) {
        meta->last_accessed = time(NULL);
        ss_save_file_metadata(ss, filename, meta);
    }
    
    log_message("SS", "Read file: %s (%ld bytes)", filename, size);
    return ERR_SUCCESS;
}

// Start write operation - Creates swap file with current content
int ss_write_start(StorageServer* ss, const char* filename, int sentence_num, const char* username) {
    // Read current file content FIRST to validate bounds
    char* current_content = NULL;
    if (ss_read_file_internal(ss, filename, &current_content) != ERR_SUCCESS) {
        return ERR_FILE_NOT_FOUND;
    }
    
    // Parse to count sentences and validate bounds
    ParsedFile* pf = parse_file(current_content);
    if (pf == NULL) {
        free(current_content);
        return ERR_INTERNAL;
    }
    
    int current_sentence_count = pf->sentence_count;
    
    // Check if we're trying to append a new sentence (sentence_num == sentence_count)
    // If so, verify that the last sentence is properly terminated with punctuation
    if (sentence_num == current_sentence_count && current_sentence_count > 0) {
        Sentence* last_sentence = &pf->sentences[current_sentence_count - 1];
        if (!is_sentence_terminated(last_sentence)) {
            log_error("SS", "Cannot append sentence %d: previous sentence not terminated with punctuation",
                     sentence_num);
            free_parsed_file(pf);
            free(current_content);
            return ERR_INVALID_SENTENCE;
        }
    }
    
    free_parsed_file(pf);
    
    // Validate sentence_num: must be 0 to current_sentence_count (inclusive, allows append)
    if (sentence_num < 0 || sentence_num > current_sentence_count) {
        log_error("SS", "Invalid sentence_num %d (file has %d sentences, can write 0-%d)",
                 sentence_num, current_sentence_count, current_sentence_count);
        free(current_content);
        return ERR_INVALID_SENTENCE;
    }
    
    // Acquire logical lock after validation
    if (acquire_sentence_lock(ss, filename, sentence_num, username) < 0) {
        free(current_content);
        return ERR_SENTENCE_LOCKED;
    }
    
    // Get paths
    char filepath[MAX_PATH];
    char swappath[MAX_PATH];
    get_file_path(ss, filename, filepath);
    get_swap_file_path(ss, filename, sentence_num, swappath);
    
    // Create backup for undo
    pthread_mutex_lock(&ss->locks_mutex);
    int undo_idx = -1;
    for (int i = 0; i < 100; i++) {
        if (!ss->undo_state[i].has_backup || strcmp(ss->undo_state[i].filename, filename) == 0) {
            undo_idx = i;
            break;
        }
    }
    
    if (undo_idx != -1) {
        if (ss->undo_state[undo_idx].prev_content != NULL) {
            free(ss->undo_state[undo_idx].prev_content);
        }
        strncpy(ss->undo_state[undo_idx].filename, filename, MAX_FILENAME - 1);
        ss->undo_state[undo_idx].filename[MAX_FILENAME - 1] = '\0';
        ss->undo_state[undo_idx].prev_content = strdup(current_content);
        ss->undo_state[undo_idx].has_backup = true;
        ss_save_undo_state(ss, undo_idx);
    }
    pthread_mutex_unlock(&ss->locks_mutex);
    
    // Copy current content to swap file
    FILE* swap_fp = fopen(swappath, "w");
    if (swap_fp == NULL) {
        log_error("SS", "Failed to create swap file for %s", filename);
        free(current_content);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    fprintf(swap_fp, "%s", current_content);
    fclose(swap_fp);
    free(current_content);
    
    log_message("SS", "Write started on %s sentence %d by %s (swap file created)", 
                filename, sentence_num, username);
    return ERR_SUCCESS;
}

// Update word in sentence - Works on swap file
int ss_write_update(StorageServer* ss, const char* filename, int sentence_num, 
                    int word_index, const char* content) {
    // Verify lock is held
    pthread_mutex_lock(&ss->locks_mutex);
    SentenceLock* lock = NULL;
    for (int i = 0; i < ss->num_locks; i++) {
        if (ss->locks[i].in_use && ss->locks[i].locked &&
            strcmp(ss->locks[i].filename, filename) == 0 && 
            ss->locks[i].sentence_num == sentence_num) {
            lock = &ss->locks[i];
            break;
        }
    }
    pthread_mutex_unlock(&ss->locks_mutex);
    
    if (lock == NULL) {
        log_error("SS", "Write update failed: sentence %d in %s is not locked", 
                 sentence_num, filename);
        return ERR_SENTENCE_LOCKED;
    }

    // Work on swap file
    char swappath[MAX_PATH];
    get_swap_file_path(ss, filename, sentence_num, swappath);
    
    // Read swap file content (contains entire file)
    FILE* swap_fp = fopen(swappath, "r");
    if (swap_fp == NULL) {
        log_error("SS", "Swap file not found for %s sentence %d", filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    fseek(swap_fp, 0, SEEK_END);
    long size = ftell(swap_fp);
    fseek(swap_fp, 0, SEEK_SET);
    
    char* file_content = (char*)malloc(size + 1);
    if (file_content == NULL) {
        fclose(swap_fp);
        return ERR_INTERNAL;
    }
    
    fread(file_content, 1, size, swap_fp);
    file_content[size] = '\0';
    fclose(swap_fp);
    
    // Parse and modify
    ParsedFile* pf = parse_file(file_content);
    free(file_content);
    
    if (pf == NULL) {
        return ERR_INVALID_SENTENCE;
    }
    
    if (pf->sentence_count == 0) {
        pf->sentences[0].words = NULL;
        pf->sentences[0].word_count = 0;
        pf->sentence_count = 1;
    }
    
    // Allow appending a new sentence (sentence_num == sentence_count)
    if (sentence_num < 0 || sentence_num > pf->sentence_count) {
        log_error("SS", "Invalid sentence %d (swap file has %d sentences)", 
                 sentence_num, pf->sentence_count);
        free_parsed_file(pf);
        return ERR_INVALID_SENTENCE;
    }
    
    // If appending a new sentence, initialize it
    if (sentence_num == pf->sentence_count) {
        if (pf->sentence_count >= MAX_SENTENCES) {
            log_error("SS", "Maximum sentence count reached");
            free_parsed_file(pf);
            return ERR_INVALID_SENTENCE;
        }
        pf->sentences[sentence_num].words = NULL;
        pf->sentences[sentence_num].word_count = 0;
        pf->sentence_count++;
    }
    
    Sentence* sent = &pf->sentences[sentence_num];
    if (word_index < 0 || word_index > sent->word_count) {
        log_error("SS", "Invalid word index %d (sentence has %d words)", 
                 word_index, sent->word_count);
        free_parsed_file(pf);
        return ERR_INVALID_WORD_INDEX;
    }
    
    // Insert the word(s)
    if (insert_word(sent, word_index, content) < 0) {
        log_error("SS", "Failed to insert word at index %d", word_index);
        free_parsed_file(pf);
        return ERR_INVALID_WORD_INDEX;
    }
    
    // Reconstruct and re-parse to handle sentence delimiters
    int pre_reparse_sentence_count = pf->sentence_count;
    char* temp_content = reconstruct_file(pf);
    free_parsed_file(pf);
    
    pf = parse_file(temp_content);
    free(temp_content);
    
    if (pf == NULL) {
        log_error("SS", "Failed to re-parse after word insertion");
        return ERR_INTERNAL;
    }
    
    // Warn if sentence count changed due to punctuation in inserted text
    if (pf->sentence_count != pre_reparse_sentence_count) {
        log_message("SS", "NOTE: Content contains sentence delimiters (!, ?, .) - created %d sentences (was %d)",
                   pf->sentence_count, pre_reparse_sentence_count);
    }
    
    // Write back to swap file with updated content
    char* new_content = reconstruct_file(pf);
    swap_fp = fopen(swappath, "w");
    if (swap_fp == NULL) {
        log_error("SS", "Failed to write to swap file");
        free(new_content);
        free_parsed_file(pf);
        return ERR_INTERNAL;
    }
    
    fprintf(swap_fp, "%s", new_content);
    fclose(swap_fp);
    
    log_message("SS", "Updated word %d in sentence %d of %s (now has %d sentences)", 
               word_index, sentence_num, filename, pf->sentence_count);
    
    free(new_content);
    free_parsed_file(pf);
    
    return ERR_SUCCESS;
}

// End write operation - Merges changes and commits atomically
int ss_write_end(StorageServer* ss, const char* filename, int sentence_num) {
    // Verify lock is held
    pthread_mutex_lock(&ss->locks_mutex);
    SentenceLock* lock = NULL;
    int lock_idx = -1;
    for (int i = 0; i < ss->num_locks; i++) {
        if (ss->locks[i].in_use && ss->locks[i].locked &&
            strcmp(ss->locks[i].filename, filename) == 0 && 
            ss->locks[i].sentence_num == sentence_num) {
            lock = &ss->locks[i];
            lock_idx = i;
            break;
        }
    }
    pthread_mutex_unlock(&ss->locks_mutex);
    
    if (lock == NULL) {
        log_error("SS", "Write end failed: sentence %d in %s is not locked", 
                 sentence_num, filename);
        return ERR_SENTENCE_LOCKED;
    }
    
    // Get paths
    char filepath[MAX_PATH];
    char swappath[MAX_PATH];
    char temppath[MAX_PATH];
    get_file_path(ss, filename, filepath);
    get_swap_file_path(ss, filename, sentence_num, swappath);
    snprintf(temppath, MAX_PATH, "%s.commit_tmp_%d", filepath, sentence_num);
    
    // Check swap file exists
    if (access(swappath, F_OK) != 0) {
        log_error("SS", "Swap file not found for %s sentence %d", filename, sentence_num);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    // Read the modified content from swap file
    char* swap_content = NULL;
    FILE* swap_fp = fopen(swappath, "r");
    if (swap_fp == NULL) {
        log_error("SS", "Failed to open swap file for %s", filename);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    fseek(swap_fp, 0, SEEK_END);
    long swap_size = ftell(swap_fp);
    fseek(swap_fp, 0, SEEK_SET);
    swap_content = (char*)malloc(swap_size + 1);
    if (swap_content == NULL) {
        fclose(swap_fp);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    fread(swap_content, 1, swap_size, swap_fp);
    swap_content[swap_size] = '\0';
    fclose(swap_fp);
    
    // Parse the swap file to extract modified sentences
    ParsedFile* swap_pf = parse_file(swap_content);
    free(swap_content);
    
    if (swap_pf == NULL) {
        log_error("SS", "Failed to parse swap file for %s", filename);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    // Acquire per-file commit mutex for atomic commit
    // This serializes commits to THIS file only, allowing concurrent writes to different files/sentences
    pthread_mutex_t* file_mutex = get_file_commit_mutex(ss, filename);
    pthread_mutex_lock(file_mutex);
    
    // Read the CURRENT file (may have been modified by other concurrent writes)
    char* current_content = NULL;
    if (ss_read_file_internal(ss, filename, &current_content) != ERR_SUCCESS) {
        log_error("SS", "Failed to read current file for merge");
        free_parsed_file(swap_pf);
        pthread_mutex_unlock(file_mutex);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    // Parse current file
    ParsedFile* current_pf = parse_file(current_content);
    free(current_content);
    
    if (current_pf == NULL) {
        log_error("SS", "Failed to parse current file for merge");
        free_parsed_file(swap_pf);
        pthread_mutex_unlock(file_mutex);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    // Check if the target sentence still exists in current file
    // Allow sentence_num == sentence_count for appending new sentences
    if (sentence_num > current_pf->sentence_count) {
        log_error("SS", "Sentence %d is out of bounds (file now has %d sentences)",
                 sentence_num, current_pf->sentence_count);
        free_parsed_file(swap_pf);
        free_parsed_file(current_pf);
        pthread_mutex_unlock(file_mutex);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INVALID_SENTENCE;
    }
    
    // CRITICAL: The swap file contains a SNAPSHOT of the entire file from WRITE_START time
    // We MUST only use sentence_num from swap_pf and ignore all other sentences
    // All other sentences should come from current_pf (which has the latest changes)
    
    // Check swap file has the sentence we modified
    if (sentence_num >= swap_pf->sentence_count) {
        log_error("SS", "Swap file is missing sentence %d (has only %d sentences)",
                 sentence_num, swap_pf->sentence_count);
        free_parsed_file(swap_pf);
        free_parsed_file(current_pf);
        pthread_mutex_unlock(file_mutex);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INVALID_SENTENCE;
    }
    
    log_message("SS", "MERGE: current file has %d sentences, swap file has %d sentences, modifying sentence %d",
               current_pf->sentence_count, swap_pf->sentence_count, sentence_num);
    
    // IMPORTANT: Extract ALL sentences from sentence_num onwards in the swap file
    // User may have created multiple sentences (e.g., "hello! world!" becomes 2 sentences)
    // We must preserve all of them
    
    // Create merged file
    ParsedFile* merged_pf = (ParsedFile*)malloc(sizeof(ParsedFile));
    merged_pf->sentences = (Sentence*)malloc(MAX_SENTENCES * sizeof(Sentence));
    merged_pf->sentence_count = 0;
    
    // Copy sentences from current file up to (but not including) sentence_num
    for (int i = 0; i < sentence_num && i < current_pf->sentence_count && merged_pf->sentence_count < MAX_SENTENCES; i++) {
        merged_pf->sentences[merged_pf->sentence_count] = current_pf->sentences[i];
        current_pf->sentences[i].words = NULL; // Transfer ownership
        current_pf->sentences[i].word_count = 0;
        merged_pf->sentence_count++;
    }
    
    // Insert ALL modified sentences from swap file (starting at sentence_num)
    for (int i = sentence_num; i < swap_pf->sentence_count && merged_pf->sentence_count < MAX_SENTENCES; i++) {
        merged_pf->sentences[merged_pf->sentence_count] = swap_pf->sentences[i];
        swap_pf->sentences[i].words = NULL; // Transfer ownership
        swap_pf->sentences[i].word_count = 0;
        merged_pf->sentence_count++;
    }
    
    // Copy remaining sentences from current file (after the modified section)
    // Skip sentence_num in current file since we replaced it
    int skip_count = (sentence_num < current_pf->sentence_count) ? 1 : 0;
    for (int i = sentence_num + skip_count; i < current_pf->sentence_count && merged_pf->sentence_count < MAX_SENTENCES; i++) {
        merged_pf->sentences[merged_pf->sentence_count] = current_pf->sentences[i];
        current_pf->sentences[i].words = NULL; // Transfer ownership
        current_pf->sentences[i].word_count = 0;
        merged_pf->sentence_count++;
    }
    
    log_message("SS", "MERGE complete: merged file has %d sentences", merged_pf->sentence_count);
    
    // Reconstruct the merged file
    char* merged_content = reconstruct_file(merged_pf);
    
    // Clean up parsed files
    free_parsed_file(swap_pf);
    free_parsed_file(current_pf);
    free_parsed_file(merged_pf);
    
    if (merged_content == NULL) {
        log_error("SS", "Failed to reconstruct merged file");
        pthread_mutex_unlock(file_mutex);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    // Write merged content to temp file
    FILE* temp_fp = fopen(temppath, "w");
    if (temp_fp == NULL) {
        log_error("SS", "Failed to create temp file for commit");
        free(merged_content);
        pthread_mutex_unlock(file_mutex);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    fprintf(temp_fp, "%s", merged_content);
    fclose(temp_fp);
    free(merged_content);
    
    // Atomic rename - commit the changes
    if (rename(temppath, filepath) != 0) {
        log_error("SS", "Failed to commit changes for %s: %s", filename, strerror(errno));
        unlink(temppath);
        pthread_mutex_unlock(file_mutex);
        release_sentence_lock(ss, filename, sentence_num);
        return ERR_INTERNAL;
    }
    
    pthread_mutex_unlock(file_mutex);
    
    log_message("SS", "Successfully merged changes for %s sentence %d", filename, sentence_num);
    
    // Clean up swap file
    unlink(swappath);
    
    // Update metadata with new file stats
    char* content = NULL;
    if (ss_read_file_internal(ss, filename, &content) == ERR_SUCCESS && content != NULL) {
        ParsedFile* pf = parse_file(content);
        if (pf != NULL) {
            int word_count = 0, char_count = 0;
            update_file_stats(pf, &word_count, &char_count);
            
            struct stat st;
            size_t file_size = (stat(filepath, &st) == 0) ? st.st_size : 0;
            
            ss_update_file_metadata(ss, filename, NULL, word_count, char_count, file_size);
            free_parsed_file(pf);
        }
        free(content);
    }
    
    // Release lock
    release_sentence_lock(ss, filename, sentence_num);
    
    log_message("SS", "Write ended on %s sentence %d (changes committed atomically)", 
                filename, sentence_num);
    return ERR_SUCCESS;
}

// Delete file
int ss_delete_file(StorageServer* ss, const char* filename) {
    char filepath[MAX_PATH];
    get_file_path(ss, filename, filepath);
    
    if (access(filepath, F_OK) != 0) return ERR_FILE_NOT_FOUND;
    if (unlink(filepath) != 0) return ERR_INTERNAL;
    
    // Clean up swap files for all sentences
    char swappath[MAX_PATH];
    for (int i = 0; i < 100; i++) {
        get_swap_file_path(ss, filename, i, swappath);
        unlink(swappath); // Ignore errors
    }
    
    char meta_path[MAX_PATH];
    snprintf(meta_path, MAX_PATH, "%s/.meta_%s", ss->storage_path, filename);
    unlink(meta_path);
    
    char undo_path[MAX_PATH];
    snprintf(undo_path, MAX_PATH, "%s/.undo_%s.bak", ss->storage_path, filename);
    unlink(undo_path);
    
    pthread_mutex_lock(&ss->metadata_mutex);
    for (int i = 0; i < ss->num_metadata; i++) {
        if (strcmp(ss->file_metadata[i].filename, filename) == 0) {
            for (int j = 0; j < ss->file_metadata[i].num_read_users; j++) 
                free(ss->file_metadata[i].read_users[j]);
            free(ss->file_metadata[i].read_users);
            for (int j = 0; j < ss->file_metadata[i].num_write_users; j++) 
                free(ss->file_metadata[i].write_users[j]);
            free(ss->file_metadata[i].write_users);
            
            for (int j = i; j < ss->num_metadata - 1; j++) 
                ss->file_metadata[j] = ss->file_metadata[j + 1];
            ss->num_metadata--;
            break;
        }
    }
    pthread_mutex_unlock(&ss->metadata_mutex);
    
    log_message("SS", "Deleted file: %s", filename);
    return ERR_SUCCESS;
}

// Undo last change
int ss_undo_file(StorageServer* ss, const char* filename) {
    pthread_mutex_lock(&ss->locks_mutex);
    
    // Check no active writes
    for (int i = 0; i < ss->num_locks; i++) {
        if (ss->locks[i].in_use && ss->locks[i].locked && 
            strcmp(ss->locks[i].filename, filename) == 0) {
            pthread_mutex_unlock(&ss->locks_mutex);
            log_error("SS", "Cannot undo %s while file is being written", filename);
            return ERR_SENTENCE_LOCKED;
        }
    }
    
    int undo_idx = -1;
    for (int i = 0; i < 100; i++) {
        if (ss->undo_state[i].has_backup && 
            strcmp(ss->undo_state[i].filename, filename) == 0) {
            undo_idx = i;
            break;
        }
    }
    
    if (undo_idx == -1 || ss->undo_state[undo_idx].prev_content == NULL) {
        pthread_mutex_unlock(&ss->locks_mutex);
        log_error("SS", "No undo history available for %s", filename);
        return ERR_INTERNAL;
    }
    
    char* backup_content = strdup(ss->undo_state[undo_idx].prev_content);
    free(ss->undo_state[undo_idx].prev_content);
    ss->undo_state[undo_idx].prev_content = NULL;
    ss->undo_state[undo_idx].has_backup = false;
    pthread_mutex_unlock(&ss->locks_mutex);
    
    char undo_path[MAX_PATH];
    snprintf(undo_path, MAX_PATH, "%s/.undo_%s.bak", ss->storage_path, filename);
    unlink(undo_path);
    
    // Use atomic rename pattern for undo too
    char filepath[MAX_PATH];
    char temppath[MAX_PATH];
    get_file_path(ss, filename, filepath);
    snprintf(temppath, MAX_PATH, "%s.undo_tmp", filepath);
    
    FILE* fp = fopen(temppath, "w");
    if (fp == NULL) {
        free(backup_content);
        return ERR_INTERNAL;
    }
    fprintf(fp, "%s", backup_content);
    fclose(fp);
    
    // Atomic rename
    rename(temppath, filepath);
    
    ParsedFile* pf = parse_file(backup_content);
    if (pf != NULL) {
        int word_count = 0, char_count = 0;
        update_file_stats(pf, &word_count, &char_count);
        ss_update_file_metadata(ss, filename, NULL, word_count, char_count, strlen(backup_content));
        free_parsed_file(pf);
    }
    
    free(backup_content);
    log_message("SS", "Undone last change to %s", filename);
    return ERR_SUCCESS;
}

// Acquire sentence lock (Fail-Fast)
int acquire_sentence_lock(StorageServer* ss, const char* filename, int sentence_num, const char* username) {
    pthread_mutex_lock(&ss->locks_mutex);
    
    int lock_idx = -1;
    int empty_idx = -1;
    for (int i = 0; i < ss->num_locks; i++) {
        if (ss->locks[i].in_use && strcmp(ss->locks[i].filename, filename) == 0 && 
            ss->locks[i].sentence_num == sentence_num) {
            lock_idx = i;
            break;
        }
        if (!ss->locks[i].in_use && empty_idx == -1) {
            empty_idx = i;
        }
    }
    
    if (lock_idx == -1) {
        if (empty_idx != -1) {
            lock_idx = empty_idx;
        } else {
            ss->locks = (SentenceLock*)realloc(ss->locks, (ss->num_locks + 1) * sizeof(SentenceLock));
            lock_idx = ss->num_locks;
            ss->num_locks++;
        }
        
        strncpy(ss->locks[lock_idx].filename, filename, MAX_FILENAME - 1);
        ss->locks[lock_idx].sentence_num = sentence_num;
        ss->locks[lock_idx].in_use = true;
        ss->locks[lock_idx].locked = false;
    }
    
    if (ss->locks[lock_idx].locked) {
        log_message("SS", "FAIL FAST: Sentence %d in %s is already locked by %s", 
                   sentence_num, filename, ss->locks[lock_idx].locked_by);
        pthread_mutex_unlock(&ss->locks_mutex);
        return -1;
    }
    
    strncpy(ss->locks[lock_idx].locked_by, username, MAX_USERNAME - 1);
    ss->locks[lock_idx].locked = true;
    ss->locks[lock_idx].locked_at = time(NULL);
    
    pthread_mutex_unlock(&ss->locks_mutex);
    
    log_message("SS", "Acquired logical lock on sentence %d in %s for %s", 
               sentence_num, filename, username);
    return 0;
}

// Release sentence lock
int release_sentence_lock(StorageServer* ss, const char* filename, int sentence_num) {
    pthread_mutex_lock(&ss->locks_mutex);
    
    for (int i = 0; i < ss->num_locks; i++) {
        if (ss->locks[i].in_use && strcmp(ss->locks[i].filename, filename) == 0 && 
            ss->locks[i].sentence_num == sentence_num && ss->locks[i].locked) {
            
            ss->locks[i].locked = false;
            ss->locks[i].locked_by[0] = '\0';
            
            log_message("SS", "Released logical lock on sentence %d in %s", 
                       sentence_num, filename);
            pthread_mutex_unlock(&ss->locks_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&ss->locks_mutex);
    log_error("SS", "No lock found to release for sentence %d in %s", sentence_num, filename);
    return -1;
}

// Stream file
void ss_stream_file(StorageServer* ss, int client_fd, const char* filename) {
    char* content = NULL;
    if (ss_read_file(ss, filename, &content) != ERR_SUCCESS || content == NULL) {
        MessageHeader err_header = {.type = MSG_ERROR, .length = 0};
        send(client_fd, &err_header, sizeof(MessageHeader), 0);
        return;
    }
    
    char* word_start = content;
    char* ptr = content;
    
    while (*ptr != '\0') {
        while (*ptr != '\0' && isspace((unsigned char)*ptr)) ptr++;
        if (*ptr == '\0') break;
        
        word_start = ptr;
        while (*ptr != '\0' && !isspace((unsigned char)*ptr)) ptr++;
        
        char word[MAX_CONTENT];
        int word_len = ptr - word_start;
        strncpy(word, word_start, word_len);
        word[word_len] = '\0';
        
        MessageHeader word_header = {.type = MSG_SUCCESS, .length = strlen(word) + 1};
        
        if (send(client_fd, &word_header, sizeof(MessageHeader), 0) <= 0 ||
            send(client_fd, word, word_header.length, 0) <= 0) {
            break; 
        }
        usleep(100000); // 100ms delay
    }
    
    MessageHeader stop_header = {.type = MSG_STOP, .length = 0};
    send(client_fd, &stop_header, sizeof(MessageHeader), 0);
    
    free(content);
    log_message("SS", "Finished streaming %s", filename);
}