#ifndef SES_UTIL_H
#define SES_UTIL_H

#include <stdint.h>
#include <unistd.h>

void info(char *format, ...);
void hexdump(char *label, uint8_t *data, size_t len);
int unhexlify(const char *ascii_hex, size_t ascii_hex_len, uint8_t *binary, size_t binary_size);

#endif
