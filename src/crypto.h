#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <linux/types.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/errno.h>

// 20 = size(u16) + size(u8) + len("tls13 ") +
//      max_len("client in", "server in", "quicv2 key", ... ) +
//      size(u8);
#define MAX_LABEL_LENGTH 20

struct decrypt_context {
        struct shash_desc *shash;      // SHA256 hash algorithm handler
	struct crypto_aead *tfm;       // AES-GCM encryption algorithm handler
	struct aead_request *req;      // pre-allocated AEAD request (avoids GFP_ATOMIC on hot path)
        u8 *orig_cipher_text_ptr;      // original encrypted data pointer, used for freeing memory when need alignment
	u8 *cipher_text;               // encrypted data
        u8 *orig_plain_text_ptr;       // original decrypted data pointer, used for freeing memory when need alignment
	u8 *plain_text;                // decrypted data
        u8 *orig_aad_data_buf;         //used to free the associated data buffer
        u8 *aad_data_buf;              //used to store the associated data
};

struct shash_desc * alloc_hash_sha256(void);
void free_hash_sha256(struct shash_desc *shash);


int hkdf_extract(struct shash_desc * shash, const u8 *salt, size_t salt_len,
                        const u8 *ikm, size_t ikm_len,
                        u8 *prk, size_t prk_len);
int build_label(u8 *out_buf, size_t max_buf_len, u16 out_key_len,
                const char *label, size_t label_len);

int hkdf_expand(struct shash_desc * shash, const char *prk, size_t prk_len, 
                const char *info, size_t info_len, 
                char *out, size_t out_len);

int aes_ecb_encrypt(const u8 *key, const size_t key_len, const u8 *input, u8 *output);



int hkdf_expand_label(struct shash_desc * shash, const u8 *prk, size_t prk_len,
                      const char *label,  size_t label_len,
                      u8 *out_key, size_t out_len);


struct decrypt_context *alloc_decrypt_context(void);
void free_decrypt_context(struct decrypt_context *ctx);
int init_decrypt_context(struct decrypt_context *ctx, const u8 *key,
                         size_t key_len);
int aes_gcm_decrypt(struct decrypt_context *ctx, const u8 *key, size_t key_len,
                               unsigned char *nonce, size_t nonce_len,
                               const u8 *ciphertext, size_t ciphertext_len,
                               const u8 *aad, size_t aad_len, u8 *output,
                               size_t *output_len, size_t max_output_len);

#endif /* _CRYPTO_H */