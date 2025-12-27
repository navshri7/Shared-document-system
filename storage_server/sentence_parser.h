#ifndef SENTENCE_PARSER_H
#define SENTENCE_PARSER_H

#include <stdbool.h>

#define MAX_WORDS_PER_SENTENCE 1000
#define MAX_SENTENCES 10000

// Sentence structure
typedef struct {
    char** words;
    int word_count;
} Sentence;

// Parsed file structure
typedef struct {
    Sentence* sentences;
    int sentence_count;
} ParsedFile;

// Check if character is a sentence delimiter
bool is_sentence_delimiter(char c);

// Parse file content into sentences and words
ParsedFile* parse_file(const char* content);

// Free parsed file structure
void free_parsed_file(ParsedFile* pf);

// Reconstruct file content from parsed structure
char* reconstruct_file(ParsedFile* pf);

// Insert word at specific position in sentence
int insert_word(Sentence* sentence, int word_index, const char* content);

// Update word count and char count for file
void update_file_stats(ParsedFile* pf, int* word_count, int* char_count);

// Check if a sentence is properly terminated with punctuation
bool is_sentence_terminated(Sentence* sentence);

#endif // SENTENCE_PARSER_H
