#include "crypto.h"

#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/printk.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "aes_nohw.h"
#include "firewalla_memory.h"
#include "utils.h"

#define PREFIX "tls13 "
#define HASH_ALGO "sha256"     // the hash algorithm used by HMAC
#define SHA_256_BLOCK_SIZE 32  // max size of SHA-256 output
#define MAX_DIGEST_SIZE 64     // max size of hash output(e.g. SHA-512 is 64)

#define AES_KEY_SIZE 16
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

struct shash_desc *alloc_hash_sha256(void) {
	struct crypto_shash *tfm = NULL;
	struct shash_desc *shash = NULL;

	// Allocate the hashing algorithm
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Failed to allocate HMAC tfm: error %ld\n",
		       PTR_ERR(tfm));
		return NULL;
	}
	// Allocate shash descriptor
	shash =
	    kmalloc_wrapper(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!shash) {
		pr_err("Failed to allocate shash\n");
		shash = NULL;
		goto out_free_tfm;
	}
	shash->tfm = tfm;

	// Success
	return shash;
out_free_tfm:
	if (tfm) crypto_free_shash(tfm);
	return NULL;
}

void free_hash_sha256(struct shash_desc *shash) {
	if (!shash) return;
	if (shash->tfm) crypto_free_shash(shash->tfm);
	kfree_wrapper(shash);
}

int hkdf_extract(struct shash_desc *shash, const u8 *salt, size_t salt_len,
                 const u8 *ikm, size_t ikm_len, u8 *output, size_t output_len) {
	struct crypto_shash *tfm = NULL;
	int ret = 0;

	if (!shash || !shash->tfm || !ikm || !output) {
		pr_err("Invalid input parameters\n");
		return -EINVAL;
	}
	tfm = shash->tfm;

	// Set the HMAC key (salt)
	ret = crypto_shash_setkey(tfm, salt, salt_len);
	if (ret) {
		pr_err("Failed to set HMAC key\n");
		return ret;
	}

	// Perform HMAC
	ret = crypto_shash_digest(shash, ikm, ikm_len, output);
	if (ret) {
		pr_err("HMAC calculation failed\n");
		return ret;
	}

	return ret;
}

// Helper function to write a 16-bit value in big-endian
static void write_u16_be(u8 *buf, u16 value) {
	if (buf == NULL) return;
	buf[0] = (value >> 8) & 0xFF;  // higher bits
	buf[1] = value & 0xFF;         // lower bits
}

// Helper function to append bytes to a buffer
static int append_bytes(u8 *buf, size_t *offset, const u8 *data, size_t len,
                        size_t max_len) {
	if (*offset + len > max_len) return -ENOMEM;

	memcpy(buf + *offset, data, len);
	*offset += len;

	return 0;
}

int build_label(u8 *out_buf, size_t max_buf_len, u16 out_key_len,
                const char *label, size_t label_len) {
	size_t offset = 0;
	int ret = 0;
	u8 label_prefix_len;

	if (!out_buf || !label) {
		pr_err("Invalid input parameters\n");
		return -EINVAL;
	}

	if (max_buf_len < MAX_LABEL_LENGTH) return -EINVAL;

	// write input key length (2 bytes)
	write_u16_be(out_buf + offset, out_key_len);
	offset += 2;

	// write label length (1 byte)
	label_prefix_len = strlen(PREFIX) + label_len;
	if (append_bytes(out_buf, &offset, &label_prefix_len, 1, max_buf_len)) {
		return -ENOMEM;
	}

	// write "tls13" + label
	if (append_bytes(out_buf, &offset, (const u8 *)PREFIX, strlen(PREFIX),
	                 max_buf_len)) {
		return -ENOMEM;
	}

	if (append_bytes(out_buf, &offset, (const u8 *)label, label_len,
	                 max_buf_len)) {
		return -ENOMEM;
	}

	// padding 0 at end of label
	if (append_bytes(out_buf, &offset, (const u8 *)"\0", 1, max_buf_len)) {
		return -ENOMEM;
	}

	// copy to output buffer
	if (offset > max_buf_len) {
		return -ENOMEM;
	}

	ret = offset;  // return the length of the generated label

	return ret;
}

int hkdf_expand(struct shash_desc *shash, const char *prk, size_t prk_len,
                const char *info, size_t info_len, char *out, size_t out_len) {
	struct crypto_shash *tfm = NULL;
	char temp[MAX_DIGEST_SIZE];  // current HMAC result
	char buf[MAX_DIGEST_SIZE + MAX_LABEL_LENGTH + 1];  // HMAC input buffer
	size_t hash_len;
	size_t n_blocks;
	size_t i;
	int ret = 0;

	if (!shash || !shash->tfm || !prk || !info || !out) {
		pr_err("Invalid input parameters\n");
		return -EINVAL;
	}
	tfm = shash->tfm;

	hash_len = crypto_shash_digestsize(tfm);

	if (out_len > hash_len * 255) {
		pr_debug("HKDF Expand: out_len (%lu) too large\n", out_len);
		return -EINVAL;
	}

	n_blocks = (out_len - 1) / hash_len + 1;

	memset(temp, 0, hash_len);  // T(0)

	ret = crypto_shash_setkey(tfm, prk, prk_len);
	if (ret) {
		pr_err("Failed to set HMAC key\n");
		return ret;
	}

	//    T(0) = empty string (zero length)
	//    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
	//    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
	//    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
	//    ...
	for (i = 1; i <= n_blocks; i++) {
		size_t copy_len;
		size_t input_len;
		memset(buf, 0, sizeof(buf));  // T(i)

		if (i == 1) {
			// first block, use empty string as input
			memcpy(buf, info, info_len);  // info
			buf[info_len] = 1;            // first block
			input_len = info_len + 1;
		} else {
			// follwup block, use T(i-1) as input
			memcpy(buf, temp, hash_len);               // T(i-1)
			memcpy(buf + hash_len, info, info_len);    // info
			buf[hash_len + info_len] = (char)(i + 1);  // i
			input_len = hash_len + info_len + 1;
		}


		ret = crypto_shash_digest(shash, buf, input_len, temp);
		if (ret) {
			pr_err("Failed to compute HMAC\n");
			return ret;
		}

		copy_len = min(hash_len, out_len);
		memcpy(out, temp, copy_len);
		out += copy_len;
		out_len -= copy_len;
	}

	return ret;
}

int hkdf_expand_label(struct shash_desc *shash, const u8 *prk, size_t prk_len,
                      const char *label, size_t label_len, u8 *out_key,
                      size_t out_len) {
	int ret;
	char label_buf[MAX_LABEL_LENGTH];
	size_t output_label_len;

	ret = build_label(label_buf, sizeof(label_buf), out_len, label,
	                  label_len);
	if (ret < 0) {
		pr_err("Failed to build label\n");
		return ret;
	}
	output_label_len = ret;

	ret = hkdf_expand(shash, prk, prk_len, label_buf, output_label_len,
	                  out_key, out_len);
	return 0;
}

int aes_ecb_encrypt(const u8 *key, const size_t key_len, const u8 *input,
                    u8 *output) {
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
	// crystal-kernel reworked the AES lib API: struct crypto_aes_ctx /
	// aes_expandkey no longer pair with aes_encrypt. Use the encryption-only
	// key (all we need for ECB single-block header protection).
	struct aes_enckey enc_key;
	ret = aes_prepareenckey(&enc_key, key, key_len);
	if (ret) {
		pr_err("Failed to prepare AES enc key, ret = %d\n", ret);
		return ret;
	}
	// perform encryption (ECB single block mode); &enc_key matches the
	// transparent union's const struct aes_enckey * member directly
	aes_encrypt(&enc_key, output, input);
	// caller is responsible for zeroizing the key material
	memzero_explicit(&enc_key, sizeof(enc_key));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 50)
	struct crypto_aes_ctx ctx;
	// initialize AES key
	ret = aes_expandkey(&ctx, key, key_len);
	if (ret) {
		pr_err("Failed to expand AES key, ret = %d\n", ret);
		return ret;
	}
	// perform encryption (ECB single bloc mode)
	aes_encrypt(&ctx, output, input);
#else
	AES_KEY pne_key;
	ret = aes_nohw_set_encrypt_key(key, 128, &pne_key);
	if (ret) {
		pr_err("Failed to set AES key, ret = %d\n", ret);
		return ret;
	}
	aes_nohw_encrypt(input, output, &pne_key);
#endif

	return 0;
}


struct decrypt_context *alloc_decrypt_context(void) {
	struct decrypt_context *ctx = NULL;
	unsigned int max_mtu;
	int ret;

	ctx = kzalloc_wrapper(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		pr_err("Failed to allocate decrypt context\n");
		return NULL;
	}

	ctx->shash = alloc_hash_sha256();
	if (!ctx->shash) {
		pr_err("Failed to allocate SHA256 hash\n");
		return NULL;
	}

	// #if defined(__x86_64)
	// ctx->tfm = crypto_alloc_aead("gcm_base(ctr(aes-generic),ghash-generic)", 0, 0); // force software implementation
	// pr_info("Using software AES-GCM implementation\n");
	// #else
	ctx->tfm = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC); // avoid async call
	// #endif
	if (IS_ERR(ctx->tfm)) {
		pr_err("Failed to allocate AEAD cipher\n");
		goto err_free_resources;
	}

	ctx->req = aead_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!ctx->req) {
		pr_err("Failed to pre-allocate AEAD request\n");
		goto err_free_resources;
	}

	max_mtu = get_max_MTU();

	ret = alloc_aligned_memory((void **)&ctx->orig_cipher_text_ptr, (void **)&ctx->cipher_text,
	                           max_mtu, ALIGN_SIZE);
	if (ret) {
		pr_err("Failed to allocate aligned memory for cipher text\n");
		goto err_free_resources;
	}
	ret = alloc_aligned_memory((void **)&ctx->orig_plain_text_ptr, (void **)&ctx->plain_text,
	                           max_mtu, ALIGN_SIZE);
	if (ret) {
		pr_err("Failed to allocate aligned memory for plain text\n");
		goto err_free_resources;
	}

	ret = alloc_aligned_memory((void **)&ctx->orig_aad_data_buf, (void **)&ctx->aad_data_buf,
	                           max_mtu, ALIGN_SIZE);
	if (ret) {
		pr_err("Failed to allocate aligned memory for associated data buffer\n");
		goto err_free_resources;
	}

	return ctx;

err_free_resources:
	if (ctx->req) aead_request_free(ctx->req);
	if (ctx->orig_plain_text_ptr) free_aligned_memory(ctx->orig_plain_text_ptr);
	if (ctx->orig_cipher_text_ptr) free_aligned_memory(ctx->orig_cipher_text_ptr);
	if (ctx->tfm) crypto_free_aead(ctx->tfm);
	if (ctx->shash) free_hash_sha256(ctx->shash);
	if (ctx) kfree_wrapper(ctx);
	return NULL;
}

void free_decrypt_context(struct decrypt_context *ctx) {
	if (!ctx) return;

	if (ctx->req) aead_request_free(ctx->req);
	if (ctx->orig_cipher_text_ptr) free_aligned_memory(ctx->orig_cipher_text_ptr);
	if (ctx->orig_plain_text_ptr) free_aligned_memory(ctx->orig_plain_text_ptr);
	if (ctx->orig_aad_data_buf) free_aligned_memory(ctx->orig_aad_data_buf);
	if (ctx->tfm) crypto_free_aead(ctx->tfm);
	if (ctx->shash) free_hash_sha256(ctx->shash);
	kfree_wrapper(ctx);
}



int init_decrypt_context(struct decrypt_context *ctx, const u8 *key,
                         size_t key_len) {
	int ret;

	if (!ctx || !key) {
		pr_err("Invalid input parameters\n");
		return -1;
	}

	// Set the key for the AEAD cipher
	ret = crypto_aead_setkey(ctx->tfm, key, key_len);
	if (ret) {
		pr_err("Failed to set AEAD key\n");
		return -1;
	}

	ret = crypto_aead_setauthsize(ctx->tfm, GCM_TAG_SIZE);
	if (ret) {
		pr_err("Failed to set AEAD authsize\n");
		return -1;
	}

	return 0;
}


int aes_gcm_decrypt(struct decrypt_context *ctx, const u8 *key, size_t key_len,
                               unsigned char *nonce, size_t nonce_len,
                               const u8 *ciphertext, size_t ciphertext_len,
                               const u8 *aad, size_t aad_len, u8 *output,
                               size_t *output_len, size_t max_output_len) {
	
	u8 __aligned(ALIGN_SIZE) aligned_tag[GCM_TAG_SIZE];
	const u8 *aligned_ciphertext = NULL;
	struct scatterlist sg_in[3];
	struct scatterlist sg_out[2];
	struct aead_request *req = NULL;
	int ret;
	

	if (!ctx || !key || !nonce || !ciphertext || !aad || !output || !output_len) {
		pr_err("Invalid input parameters\n");
		return -EINVAL;
	}


	if (ciphertext_len < GCM_TAG_SIZE) {
		pr_debug("Invalid ciphertext length: expected at least %d, got %zu\n",
		       GCM_TAG_SIZE, ciphertext_len);
		return -EINVAL;
	}
	if (max_output_len < ciphertext_len - GCM_TAG_SIZE) {
		pr_err("Output buffer too small: expected at least %zu, got %zu\n",
		       ciphertext_len - GCM_TAG_SIZE, max_output_len);
		return -EINVAL;
	}

	pr_debug("before init_decrypt_context\n");
	ret = init_decrypt_context(ctx, key, key_len);
	if (ret) {
		pr_err("Failed to initialize decrypt context\n");
		return ret;
	}


	req = ctx->req;

	pr_debug("before align_memory\n");
	//TODO: optimize this memcpy
	if (is_aligned(ciphertext, ALIGN_SIZE)) {
		aligned_ciphertext = ciphertext;
	} else {
		memcpy(ctx->cipher_text, ciphertext, ciphertext_len);
		aligned_ciphertext = ctx->cipher_text;
	}

	memcpy(aligned_tag, ciphertext + ciphertext_len - GCM_TAG_SIZE,
	       GCM_TAG_SIZE);


	sg_init_table(sg_in, ARRAY_SIZE(sg_in));
	sg_init_table(sg_out, ARRAY_SIZE(sg_out));

	pr_debug("before sg_set_buffer");
	
	sg_set_buf(&sg_in[0], aad, aad_len);  // assoc data
	sg_set_buf(&sg_in[1], aligned_ciphertext,
	           ciphertext_len - GCM_TAG_SIZE);         // Input ciphertext
	sg_set_buf(&sg_in[2], aligned_tag, GCM_TAG_SIZE);  // Authentication tag
	sg_set_buf(&sg_out[0], aad,
	           aad_len);  // Decrypted output associated data part
	sg_set_buf(&sg_out[1], output,
	           ciphertext_len - GCM_TAG_SIZE);  // Decrypted output buffer

	pr_debug("before aead_request_set_crypt\n");
	aead_request_set_crypt(req, sg_in, sg_out, ciphertext_len, nonce);
	pr_debug("before aead_request_set_ad\n");
	aead_request_set_ad(req, aad_len);

	pr_debug("before crypto_aead_decrypt\n");
	/* Perform decryption */
	ret = crypto_aead_decrypt(req);
	if (ret) {
		pr_debug("QUIC: AES-GCM decryption failed: %d\n", ret);
	} else {
		pr_debug("Decryption succeeded\n");
		*output_len = ciphertext_len - GCM_TAG_SIZE;
	}


	return ret;
}