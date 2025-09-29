#include <glib.h>
#include <stdarg.h>
#include <stdio.h>

#include "ses_utils.h"

void hexdump(char *label, uint8_t *data, size_t len)
{
    fprintf(stderr, "%s: ", label);
    for (size_t i=0; i<len; i++) fprintf(stderr, "%02x", data[i]);
    fprintf(stderr, "\n");
}

/**
 * Convert a hexadecimal dump to a binary
 * @param ascii_hex       a string of characters [a-fA-F0-9]
 * @param ascii_hex_len   length of ascii_hex. Must be a multiple of 2
 * @param binary          output buffer where the binary gets written to
 * @param binary_size     size of the output buffer
 * @return length of the resulting binary (within binary_size)
 *         or error:
 *             -1 ascii_hex_len not a multiple of 2
 *             -2 binary_size less then ascii_hex_len/2
 *             -3 ascii_hex contains invalid characters
 * Examples:
 * "0123456"  -> -1
 * "21f_4f"   -> -3
 * "012345aF" -> 4, binary="\x01\x23\x45\xaf"
 */
int unhexlify(const char *ascii_hex, size_t ascii_hex_len, uint8_t *binary, size_t binary_size)
{
    size_t i;
    if (ascii_hex_len == 0) return 0;
    if (ascii_hex_len % 2 != 0) return -1;
    if (ascii_hex_len / 2 > binary_size) return -2;
    for (i=0; i<ascii_hex_len; i+=2) {
        int digit1 = g_ascii_xdigit_value(ascii_hex[i]);
        if (digit1 < 0) return -3;
        int digit2 = g_ascii_xdigit_value(ascii_hex[i+1]);
        if (digit2 < 0) return -3;
        *binary = 16*digit1 + digit2;
        binary++;
    }
    return ascii_hex_len / 2;
}
