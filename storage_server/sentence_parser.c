#include "sentence_parser.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Check if character is a sentence delimiter
bool is_sentence_delimiter(char c) {
    return (c == '.' || c == '!' || c == '?');
}

// Parse file content into sentences and words
ParsedFile* parse_file(const char* content) {
    if (content == NULL) return NULL;
    
    ParsedFile* pf = (ParsedFile*)malloc(sizeof(ParsedFile));
    pf->sentences = (Sentence*)malloc(MAX_SENTENCES * sizeof(Sentence));
    pf->sentence_count = 0;
    
    char* content_copy = strdup(content);
    char* ptr = content_copy;
    
    // Current sentence words
    char** current_words = (char**)malloc(MAX_WORDS_PER_SENTENCE * sizeof(char*));
    int current_word_count = 0;
    
    // Current word being built
    char word_buffer[MAX_CONTENT];
    int word_len = 0;
    
    while (*ptr != '\0') {
        char c = *ptr;
        
        if (isspace(c)) {
            // End of word
            if (word_len > 0) {
                word_buffer[word_len] = '\0';
                current_words[current_word_count] = strdup(word_buffer);
                current_word_count++;
                word_len = 0;
            }
            ptr++;
        } else if (is_sentence_delimiter(c)) {
            // Sentence delimiter - add it to current word, then finish sentence
            word_buffer[word_len++] = c;
            word_buffer[word_len] = '\0';
            
            if (word_len > 0) {
                current_words[current_word_count] = strdup(word_buffer);
                current_word_count++;
                word_len = 0;
            }
            
            // Create sentence
            if (current_word_count > 0) {
                Sentence* sent = &pf->sentences[pf->sentence_count];
                sent->words = (char**)malloc(current_word_count * sizeof(char*));
                sent->word_count = current_word_count;
                
                for (int i = 0; i < current_word_count; i++) {
                    sent->words[i] = current_words[i];
                }
                
                pf->sentence_count++;
                current_word_count = 0;
            }
            
            ptr++;
        } else {
            // Regular character - add to current word
            word_buffer[word_len++] = c;
            ptr++;
        }
    }
    
    // Handle remaining word
    if (word_len > 0) {
        word_buffer[word_len] = '\0';
        current_words[current_word_count] = strdup(word_buffer);
        current_word_count++;
    }
    
    // Handle remaining sentence (without delimiter)
    if (current_word_count > 0) {
        Sentence* sent = &pf->sentences[pf->sentence_count];
        sent->words = (char**)malloc(current_word_count * sizeof(char*));
        sent->word_count = current_word_count;
        
        for (int i = 0; i < current_word_count; i++) {
            sent->words[i] = current_words[i];
        }
        
        pf->sentence_count++;
    }
    
    free(current_words);
    free(content_copy);
    
    return pf;
}

// Free parsed file structure
void free_parsed_file(ParsedFile* pf) {
    if (pf == NULL) return;
    
    for (int i = 0; i < pf->sentence_count; i++) {
        for (int j = 0; j < pf->sentences[i].word_count; j++) {
            free(pf->sentences[i].words[j]);
        }
        free(pf->sentences[i].words);
    }
    free(pf->sentences);
    free(pf);
}

// Reconstruct file content from parsed structure
char* reconstruct_file(ParsedFile* pf) {
    if (pf == NULL) return NULL;
    
    // Estimate size
    int total_size = 0;
    for (int i = 0; i < pf->sentence_count; i++) {
        for (int j = 0; j < pf->sentences[i].word_count; j++) {
            total_size += strlen(pf->sentences[i].words[j]) + 1; // +1 for space
        }
    }
    
    char* result = (char*)malloc(total_size + 1000); // Extra buffer
    result[0] = '\0';
    
    for (int i = 0; i < pf->sentence_count; i++) {
        Sentence* sent = &pf->sentences[i];
        
        for (int j = 0; j < sent->word_count; j++) {
            strcat(result, sent->words[j]);
            
            // Add space after word (except last word in sentence if it ends with delimiter)
            if (j < sent->word_count - 1) {
                strcat(result, " ");
            } else {
                // Check if last word ends with delimiter
                char* last_word = sent->words[j];
                int len = strlen(last_word);
                if (len > 0 && !is_sentence_delimiter(last_word[len-1])) {
                    // No delimiter, might add space if there's another sentence
                    if (i < pf->sentence_count - 1) {
                        strcat(result, " ");
                    }
                } else {
                    // Has delimiter, add space before next sentence
                    if (i < pf->sentence_count - 1) {
                        strcat(result, " ");
                    }
                }
            }
        }
    }
    
    return result;
}

// Insert word at specific position in sentence
int insert_word(Sentence* sentence, int word_index, const char* content) {
    if (sentence == NULL || content == NULL) return -1;
    
    // word_index can be 0 to word_count (append at end)
    if (word_index < 0 || word_index > sentence->word_count) {
        return -1;
    }
    
    // Parse content into words (might contain sentence delimiters)
    char* content_copy = strdup(content);
    char* words_to_add[100];
    int num_words_to_add = 0;
    
    char* token = strtok(content_copy, " ");
    while (token != NULL && num_words_to_add < 100) {
        words_to_add[num_words_to_add++] = strdup(token);
        token = strtok(NULL, " ");
    }
    free(content_copy);
    
    // Reallocate words array
    int new_word_count = sentence->word_count + num_words_to_add;
    char** new_words = (char**)malloc(new_word_count * sizeof(char*));
    
    // Copy words before insertion point
    for (int i = 0; i < word_index; i++) {
        new_words[i] = sentence->words[i];
    }
    
    // Insert new words
    for (int i = 0; i < num_words_to_add; i++) {
        new_words[word_index + i] = words_to_add[i];
    }
    
    // Copy words after insertion point
    for (int i = word_index; i < sentence->word_count; i++) {
        new_words[i + num_words_to_add] = sentence->words[i];
    }
    
    // Update sentence
    free(sentence->words);
    sentence->words = new_words;
    sentence->word_count = new_word_count;
    
    return 0;
}

// Update word count and char count for file
void update_file_stats(ParsedFile* pf, int* word_count, int* char_count) {
    *word_count = 0;
    *char_count = 0;
    
    for (int i = 0; i < pf->sentence_count; i++) {
        for (int j = 0; j < pf->sentences[i].word_count; j++) {
            (*word_count)++;
            *char_count += strlen(pf->sentences[i].words[j]);
        }
        // Add spaces between words
        if (pf->sentences[i].word_count > 0) {
            *char_count += pf->sentences[i].word_count - 1;
        }
    }
    // Add spaces between sentences
    if (pf->sentence_count > 1) {
        *char_count += pf->sentence_count - 1;
    }
}

// Check if a sentence is properly terminated with punctuation
bool is_sentence_terminated(Sentence* sentence) {
    if (sentence == NULL || sentence->word_count == 0) {
        return false;
    }
    
    // Check if the last word ends with a sentence delimiter
    char* last_word = sentence->words[sentence->word_count - 1];
    int len = strlen(last_word);
    
    if (len > 0 && is_sentence_delimiter(last_word[len - 1])) {
        return true;
    }
    
    return false;
}
