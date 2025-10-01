#ifndef SES_CRYPTO_H
#define SES_CRYPTO_H

#include <glib.h>
#include <stdint.h>
#include <openssl/pem.h>

typedef struct {
	EVP_PKEY *public_key;
	const char *filename; // certificate file that contains the public key
} public_key_t;


EVP_PKEY *load_public_key(const char *path);
int authenticate_script(uint8_t *script, size_t len, GArray *public_keys, gchar const **filename, GError **error);

#endif
