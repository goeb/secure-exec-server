#include <errno.h>
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

#include "ses_crypto.h"
#include "ses_utils.h"

#define SIG_SIZE_MAX 4096 // max size of the hex dump of the signature

GQuark ses_crypto_error_quark (void);
#define SES_CRYPTO_ERROR (ses_crypto_error_quark ())
G_DEFINE_QUARK(ses-crypto-quark, ses_crypto_error)
enum {
    SES_CRYPTO_ERROR_INVALID_INPUT,
    SES_CRYPTO_ERROR_AUTHENTICATION_FAILED
};

int verify(const uint8_t *msg, size_t msg_len, EVP_PKEY *pubkey, uint8_t *sig, size_t sig_len)
{
	int ret = -1; // failure by default

	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	int status;

	status = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey);
	if (status != 1) goto error;

	status = EVP_DigestVerifyUpdate(mdctx, msg, msg_len);
	if (status != 1) goto error;

	status = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
	if (status != 1) goto error;
 
	ret = 0; // success

error:
	EVP_MD_CTX_destroy(mdctx);
	return ret;
}

/* Get the public key of X509 certificate (PEM)
 *
 * @param path   Path of the input file (PEM)
 *
 * @return pointer to public key or NULL on error
 *         The caller of the function takes ownership of the data
 *         and must free it with EVP_PKEY_free().
 */
EVP_PKEY *load_public_key(const char *path)
{
	FILE *certfile = NULL;
	X509 *x509cert = NULL;

	certfile = fopen(path, "r");
	if (!certfile) {
        fprintf(stderr, "Cannot open '%s': %s\n", path, g_strerror(errno));
		return NULL;
	}

	// Load the X509 PEM certificate
	x509cert = PEM_read_X509(certfile, NULL, 0, NULL);
	if (!x509cert) {
		fprintf(stderr, "Cannot load x509 certificate\n");
        fclose(certfile);
        return NULL;
	}

    // Get the public key
    EVP_PKEY *pubkey = X509_get_pubkey(x509cert);
    if (!pubkey) {
        fprintf(stderr, "Cannot get public key\n");
    }
	fclose(certfile);
    X509_free(x509cert);
    return pubkey;
}

static uint8_t *get_signature_from_first_line(uint8_t *script, size_t len, uint8_t *signature, size_t signature_size, size_t *signature_len, GError **error)
{
    if (len < 2) {
        g_set_error(error, SES_CRYPTO_ERROR, SES_CRYPTO_ERROR_INVALID_INPUT, "too short");
        return NULL;
    }
    uint8_t *ptr = script;
    // get the signature
    if (*ptr != '#') {
        g_set_error(error, SES_CRYPTO_ERROR, SES_CRYPTO_ERROR_INVALID_INPUT, "missing # on first line");
        return NULL;
    }
    ptr++; len--;
    // skip SPACE characters
    while (len > 0 && *ptr == ' ') {
        ptr++; len--;
    }
    if (len == 0) {
        g_set_error(error, SES_CRYPTO_ERROR, SES_CRYPTO_ERROR_INVALID_INPUT, "missing signature line");
        return NULL;
    }
    uint8_t *sig_start = ptr;
    // get the first '\n' that marks the end of the first line
    while (len > 0 && *ptr != '\n') {
        ptr++; len--;
    }

    if (len == 0) {
        g_set_error(error, SES_CRYPTO_ERROR, SES_CRYPTO_ERROR_INVALID_INPUT, "missing LF character at end of signature line");
        return NULL;
    }
    size_t sig_len = ptr - sig_start;

    int n = unhexlify((char*)sig_start, sig_len, signature, signature_size);
    if (n < 0) {
        g_set_error(error, SES_CRYPTO_ERROR, SES_CRYPTO_ERROR_INVALID_INPUT, "cannot get valid signature: %d", n);
        return NULL;
    }
    *signature_len = n;
    ptr++; // skip past the '\n'
    return ptr;
}
/* Authenticate a script
 *
 * @param script
 * @param len
 * @param public_key
 * @return 0 if authentication is ok
 *         -1 if authentication failed
 * The first line of the script must contain the signature in the format:
 * "#" <spaces> <hexadecimal dump> "\n"
 * The payload is everything that follows and is verified.
 */
int authenticate_script(uint8_t *script, size_t len, EVP_PKEY *public_key, GError **error)
{
    uint8_t signature[SIG_SIZE_MAX];
    size_t signature_len;
    uint8_t *payload_start = get_signature_from_first_line(script, len, signature, SIG_SIZE_MAX, &signature_len, error);
    if (!payload_start) return -1;

    size_t payload_len = len - (payload_start - script);
    int err = verify(payload_start, payload_len, public_key, signature, signature_len);
    if (err) {
        g_set_error(error, SES_CRYPTO_ERROR, SES_CRYPTO_ERROR_AUTHENTICATION_FAILED, "verification failed");
    }

    return err;
}

