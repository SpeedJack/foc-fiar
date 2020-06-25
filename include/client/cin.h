#ifndef CLIENT_CIN_H
#define CLIENT_CIN_H

#include <stdbool.h>

#define MAX_CMD_SIZE		64

typedef bool cmd_validity_cb(char *cmd);

extern unsigned int cin_flush_stdin(void);
extern int cin_read_line(char *buffer, int size);
extern char cin_read_char(void);
extern char read_command(char prompt, char *params, cmd_validity_cb *validity_cb);
extern char *ask_password(const char *prompt);

#endif /* CLIENT_CIN_H */
