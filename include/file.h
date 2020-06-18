#ifndef COMMON_FILE_H
#define COMMON_FILE_H

#include <stdio.h>
#include <stddef.h>

extern FILE *file_open(const char *filename, const char *mode, size_t *len);
extern unsigned char *file_read(const char *filename, size_t *len);
extern ssize_t file_write(const char *filename, const unsigned char *buffer, const size_t len);
extern unsigned char *file_readb(const char *filename, size_t *len);
extern ssize_t file_writeb(const char *filename, const unsigned char *buffer, const size_t len);
#endif /* COMMON_FILE_H */
