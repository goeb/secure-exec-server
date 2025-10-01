#ifndef SES_UTIL_H
#define SES_UTIL_H

#include <stdint.h>
#include <unistd.h>

#define INFO(...) do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#define DEBUG(...) //do { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } while (0)

int unhexlify(const char *ascii_hex, size_t ascii_hex_len, uint8_t *binary, size_t binary_size);

#endif
