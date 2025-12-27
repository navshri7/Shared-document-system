#ifndef COMMANDS_H
#define COMMANDS_H

typedef enum {
    CMD_VIEW,
    CMD_READ,
    CMD_CREATE,
    CMD_WRITE,
    CMD_DELETE,
    CMD_INFO,
    CMD_STREAM,
    CMD_LIST,
    CMD_ADDACCESS,
    CMD_REMACCESS,
    CMD_EXEC,
    CMD_UNDO,
    CMD_ETIRW,
    CMD_UNKNOWN
} CommandType;

typedef struct {
    CommandType type;
    char* args[10];
    int num_args;
    char flags[16];
} ParsedCommand;

ParsedCommand* parse_command(const char* input);
void free_parsed_command(ParsedCommand* cmd);

#endif // COMMANDS_H
