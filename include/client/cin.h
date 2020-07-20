#ifndef CLIENT_CIN_H
#define CLIENT_CIN_H

#include <stdarg.h>
#include <stdbool.h>

#define MAX_CMD_SIZE		64

typedef bool cmd_validity_cb(char *cmd, bool has_params);

extern unsigned int cin_flush_stdin(void);
extern int cin_read_line(char *buffer, int size);
extern int cin_read_uint(void);
extern char cin_read_char(void);
extern bool cin_ask_question(bool default_yes, const char *question, ...);
extern char cin_read_command(char *params, cmd_validity_cb *validity_cb);
extern char *cin_ask_passphrase(const char *username, int size);

#endif /* CLIENT_CIN_H */
