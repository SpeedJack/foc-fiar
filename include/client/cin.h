#ifndef CLIENT_CIN_H
#define CLIENT_CIN_H

extern unsigned int cin_flush_stdin();
extern int cin_read_line(char *buffer, int size);
extern char cin_read_char();
extern char *ask_password(const char *prompt);

#endif /* CLIENT_CIN_H */
