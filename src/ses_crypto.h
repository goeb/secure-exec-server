#ifndef SES_CRYPTO_H
#define SES_CRYPTO_H

#include <glib.h>
#include <stdint.h>
#include <openssl/pem.h>

EVP_PKEY *load_public_key(const char *path);
int verify(const uint8_t *msg, size_t msg_len, EVP_PKEY *pubkey, uint8_t *sig, size_t sig_len);
int authenticate_script(uint8_t *script, size_t len, EVP_PKEY *public_key, GError **error);

#endif

