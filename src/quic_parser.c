#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>


#include "quic_parser.h"
#include "crypto.h"
#include "quic_conversation.h"
#include "sample_quic_packet.h"
#include "utils.h"
#include "firewalla_memory.h"
#include "quic_cache.h"

#define TLS_HANDSHAKE 0x16
#define TLS_VERSION 0x0303
#define HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define EXTENSION_TYPE_SNI 0x0000

#define QUIC_LONG_HEADER_FORM 1 << 7
#define QUIC_INITIAL_PACKET_TYPE 0x00

#define AES_KEY_LENGTH 16
#define AES_BLOCK_SIZE 16

const u8 INITIAL_SALT[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                             0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                             0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};



// Helper to decode variable-length integers
static int64_t decode_varint(const u8 *data, size_t *offset, size_t length) {
	u8 first_byte;
	u64 value = 0;
	size_t len = 0;

	if (data == NULL || offset == NULL || *offset + 1 >= length) {
		pr_debug("Invalid input pointers\n");
		return -1;
	}

	first_byte = data[*offset];

	if ((first_byte & 0xC0) == 0x00) {
		len = 1;
		if (*offset + 1 >= length) return -1;
		value = first_byte & 0x3F;
	} else if ((first_byte & 0xC0) == 0x40) {
		len = 2;
		if (*offset + 2 >= length) return -1;
		value = ((first_byte & 0x3F) << 8) | data[*offset + 1];
	} else if ((first_byte & 0xC0) == 0x80) {
		len = 4;
		if (*offset + 4 >= length) return -1;
		value = ((first_byte & 0x3F) << 24) |
		        (data[*offset + 1] << 16) | (data[*offset + 2] << 8) |
		        data[*offset + 3];
	} else {
		len = 8;
		if (*offset + 8 >= length) return -1;
		value = ((u64)(first_byte & 0x3F) << 56) |
		        ((u64)data[*offset + 1] << 48) |
		        ((u64)data[*offset + 2] << 40) |
		        ((u64)data[*offset + 3] << 32) |
		        (data[*offset + 4] << 24) | (data[*offset + 5] << 16) |
		        (data[*offset + 6] << 8) | data[*offset + 7];
	}

	if (*offset + len > length) {
		pr_debug("Truncated data after varint decoding\n");
		return -1;
	}

	*offset += len;
	return value;
}


/*
 * Extract SNI from TLS ClientHello
 * return 0 on success, -1 on error
 */
static int extract_sni(const u8 *data, size_t length, char *output_sni,
                       size_t output_sni_len) {
	size_t offset = 0;
	u8 session_id_length;
	u8 compression_methods_length;
	u16 extensions_length;
	u16 cipher_suites_length;
	/*
	 * 1byte type, 3byte version, 32byte random, 1byte session_id_length,
	 * 1byte cipher_suites_length, 2byte cipher suite, 1byte compression_methods_length,
	 * 2byte extensions_length
	 */
	u16 minimal_client_hello_length = 43;

	if (data == NULL || output_sni == NULL || output_sni_len == 0) {
		pr_debug("Invalid input pointers\n");
		return -1;
	}
	if (length < minimal_client_hello_length) {
		pr_debug("ClientHello too short\n");
		return -1;
	}

	// Check Handshake Layer
	if (data[offset] != 0x01) {  // check if it's a ClientHello
		pr_debug("Not a ClientHello message\n");
		return -1;
	}

	// Skip Handshake header (4 bytes)
	offset += 4; // current offset is 4

	// Skip protocol version (2 bytes)
	offset += 2; // current offset is 6

	// Skip Random (32 bytes)
	offset += 32; // current offset is 38

	// Skip Session ID
	session_id_length = data[offset]; // normally 0
	if (session_id_length > 32) {
		pr_debug("Session ID too long\n");
		return -1;
	}
	offset += 1 + session_id_length; // current offset is 39 + session_id_length

	// Skip Cipher Suites
	if (offset + 2 > length) return -1;
	cipher_suites_length = pntoh16(data + offset);
	offset += 2 + cipher_suites_length;

	// Skip Compression Methods
	if (offset >= length) return -1;
	compression_methods_length = data[offset];
	offset += 1 + compression_methods_length;

	// Check for Extensions
	if (offset + 2 > length) return -1;
	extensions_length = pntoh16(data + offset);
	offset += 2;

	while (offset + 4 <= length) {
		// Parse extension type and length
		u16 extension_type = pntoh16(data + offset);
		u16 extension_length = pntoh16(data + offset + 2);
		offset += 4; //skip extension type and length

		if (offset + extension_length > length) break;

		if (extension_type == 0x0000) {  // SNI extension
			u16 sni_list_length;
			u8 server_name_type;
			u16 server_name_length;
			size_t tmp_offset = offset;

			pr_debug("parse sni\n");
			// Parse SNI, 
			if (extension_length < 8 || length < offset + extension_length) {
				pr_debug("SNI extension too short or imcomplete sni\n");
				return -1;
			}

			sni_list_length = pntoh16(data + tmp_offset);
			if (sni_list_length + 2 > extension_length){
				pr_debug("sni_list_length not match with extension_length\n");
				return -1;
			}
			tmp_offset += 2; // skip sni_list_length, total tmp_offset increament 2

			// Parse first ServerName
			server_name_type = data[tmp_offset];
			if (server_name_type != 0x00) {
				pr_debug("wrong server_name_type\n");
				return -1;
			}
			tmp_offset += 1; // skip server_name_type, total tmp_offset increament 3

			server_name_length = pntoh16(data + tmp_offset);
			tmp_offset += 2; // skip server_name_length, total tmp_offset increament 5
			
			if (server_name_length + 5 > extension_length) {
				pr_debug("server_name_length not match with extension_length\n");
				return -1;
			}

			if (output_sni_len < server_name_length + 1) {
				pr_err(
				    "output_sni_len too small, need %d, but "
				    "only have %zu\n",
				    server_name_length + 1, output_sni_len);
				return -1;
			}
			// Return the ServerName as a string
			memcpy(output_sni, data + offset + 5,
			       server_name_length);
			memset(output_sni + server_name_length, 0, 1); // append \0 to the end
			pr_debug("output_sni:%s\n", output_sni);
			return 0;
		}

		offset += extension_length;
	}

	pr_debug("SNI not found\n");
	return -1;
}

/**
 * Process QUIC CRYPTO frame
 * return -1 on error;
 * return 0 on success. 
 */
static int process_crypto_frame(const u_char *data, size_t length,
                                struct conversation *conv,
                                struct packet_info *pinfo,
                                size_t *offset) {
	size_t tmp_offset = *offset;
	size_t offset_of_crypto_data = 0;
	size_t backup_offset;
	int64_t offset_of_CRYPTO;
	int64_t crypto_length;
	int ret = -1;

	tmp_offset += 1;  // skip frame type
	offset_of_CRYPTO = decode_varint(data, &tmp_offset, length);
	if (offset_of_CRYPTO == -1) {
		pr_debug("Failed to decode offset_of_CRYPTO\n");
		return -1;
	}

	pr_debug("Offset of CRYPTO:%lld\n", offset_of_CRYPTO);

	crypto_length = decode_varint(data, &tmp_offset, length);
	if (crypto_length == -1) {
		pr_debug("Failed to decode crypto_length\n");
		return -1;
	}
	pr_debug("CRYPTO length:%llu\n", (unsigned long long)crypto_length);
	if ((size_t)crypto_length + tmp_offset > length) {
		pr_debug("Incomplete CRYPTO frame\n");
		return -1;
	}
	offset_of_crypto_data = tmp_offset;
	backup_offset = tmp_offset + crypto_length;

	if (crypto_length > MAX_CRYPTO_BUFFER_SIZE) {
		pr_debug(
		    "CRYPTO data buffer is too small, "
		    "need %llu bytes, "
		    "but only have %d bytes\n",
		    (unsigned long long)crypto_length, MAX_CRYPTO_BUFFER_SIZE);
		update_conversation_status_and_free_frames(conv, ERROR);
		return -1;
	}
	// print_packet_info(&conv->pinfo);
	ret = add_frame_to_conversation(conv, data + offset_of_crypto_data, offset_of_CRYPTO,
	                          crypto_length);
	if (ret < 0) {
		pr_debug("add_frame_to_conversation error:%d\n", ret);
		update_conversation_status_and_free_frames(conv, ERROR);
		return -1;
	}

	*offset = backup_offset;
	pr_debug("offset after skip crypto data:%zu\n", *offset);

	return 0;
}

int process_ack_frame(const u_char * data, size_t length, size_t *offset) {
	size_t tmp_offset = *offset;
	u8 type;
	int64_t largest_acknowledged;
	int64_t ack_delay;
	int64_t ack_range_count;
	int64_t first_ack_range;

	type = data[tmp_offset];
	pr_debug("frame_type:%d\n", type);
	tmp_offset += 1;  // skip type

	// Largest Acknowledged
	largest_acknowledged = decode_varint(data, &tmp_offset, length);  // largest_acknowledged
	if (largest_acknowledged == -1) {
		pr_debug("Failed to decode largest_acknowledged\n");
		return -1;
	}
	pr_debug("largest_acknowledged:%lld, offset:%zu\n", largest_acknowledged, tmp_offset);	

	// ACK delay
	ack_delay = decode_varint(data, &tmp_offset, length);  
	if (ack_delay == -1) {
		pr_debug("Failed to decode ack_delay\n");
		return -1;
	}
	pr_debug("ack_delay:%lld, offset:%zu\n", ack_delay, tmp_offset);

	// ACK range count
	ack_range_count = decode_varint(data, &tmp_offset, length);  
	if (ack_range_count == -1) {
		pr_debug("Failed to decode ack_range_count\n");
		return -1;
	}
	pr_debug("ack_range_count:%lld, offset:%zu\n", ack_range_count, tmp_offset);


	// First ACK Range
	first_ack_range = decode_varint(data, &tmp_offset, length);
	if (first_ack_range == -1) {
		pr_debug("Failed to decode first_ack_range\n");
		return -1;
	}
	pr_debug("first_ack_range:%lld, offset:%zu\n", first_ack_range, tmp_offset);

	// ACK Ranges
	if (ack_range_count > 1) {
		int i;
		for (i = 0; i < ack_range_count - 1; i++) {
			int64_t gap;
			int64_t ack_range_length;

			gap = decode_varint(data, &tmp_offset, length);  // gap
			if (gap == -1) {
				pr_debug("Failed to decode gap\n");
				return -1;
			}
			pr_debug("gap:%lld, offset:%zu\n", gap, tmp_offset);
			ack_range_length = decode_varint(data, &tmp_offset, length);  // ack range length
			if (ack_range_length == -1) {
				pr_debug("Failed to decode ack_range_length\n");
				return -1;
			}
			pr_debug("ack_range_length:%lld, offset:%zu\n", ack_range_length, tmp_offset);
		}
	}

	if (type == 0x03) {  // ACK_ECN
		int i;
		// ECN Counts
		for (i = 0; i < 3; i++) {
			int64_t ecn_count;

			ecn_count = decode_varint(data, &tmp_offset, length);  // ecn count
			if (ecn_count == -1) {
				pr_debug("Failed to decode ecn_count\n");
				return -1;
			}
			pr_debug("ecn_count:%lld, offset:%zu\n", ecn_count, tmp_offset);
		}
	}

	*offset = tmp_offset;  // rewrite the offset to skip the ack frame
	
	return 0;
}


int process_connection_close_frame(const u_char * data, size_t length, size_t *offset) {
	size_t tmp_offset = *offset;

	u8 type;
	int64_t error_code;
	int64_t frame_type;
	int64_t reason_length;

	type = data[tmp_offset];
	pr_debug("frame_type:%d\n", type);
	tmp_offset += 1;  // skip type

	// Error Code
	error_code = decode_varint(data, &tmp_offset, length);  // error_code
	if (error_code == -1) {
		pr_debug("Failed to decode error_code\n");
		return -1;
	}
	pr_debug("error_code:%lld, offset:%zu\n", error_code, tmp_offset);

	if (type == 0x1c) {  // Application Close does not include Frame Type
		//Frame Type
		frame_type = decode_varint(data, &tmp_offset, length);  // frame_type
		if (frame_type == -1) {
			pr_debug("Failed to decode frame_type\n");
			return -1;
		}
		pr_debug("frame_type:%lld, offset:%zu\n", frame_type, tmp_offset);
	}
	reason_length = decode_varint(data, &tmp_offset, length);  // reason_length
	if (reason_length == -1) {
		pr_debug("Failed to decode reason_length\n");
		return -1;
	}
	pr_debug("reason_length:%lld, offset:%zu\n", reason_length, tmp_offset);

	if (tmp_offset + reason_length > length) {
		pr_debug("reason_length too large\n");
		return -1;
	}
	
	tmp_offset += reason_length;  // skip reason

	*offset = tmp_offset;  // rewrite the offset to skip the connection close frame

	return 0;
}

/**
 * Process QUIC frames
 * return -1 on error;
 * return sni length on sni is found and output_sni, output_sni_len will be set
 * accordingly. return 0 on no sni found and other secnarios.
 */
static int process_quic_frames(const u_char *data, size_t length,
                               struct conversation *conv,
                               struct packet_info *pinfo,
                               char *output_sni, size_t output_sni_len) {
	u8 packet_type;
	size_t offset = 0;
	int is_connection_close = 0;
	int is_frame_complete = 0;
	int ret;

	if (data == NULL || output_sni == NULL) {
		pr_debug("Invalid input pointers\n");
		return -1;
	}
	if (length < 1) {
		pr_debug("QUIC packet too short\n");
		return -1;
	}
	if (conv == NULL) {
		pr_debug("Conversation is NULL\n");
		return -1;
	}


	while (offset < length) {
		packet_type = data[offset];
		switch (packet_type) {
			case 0x00:  // Padding
				offset += 1;
				break;
			case 0x01:  // Ping
				offset += 1;
				break;
			case 0x06:  // Crypto
				pr_debug("QUIC Crypto frame at offset %zu\n",
					offset);
				ret = process_crypto_frame(data, length, conv, pinfo, &offset);
				pr_debug("offset after skip crypto data:%zu\n", offset);
				if (ret < 0) {
					pr_debug("process_crypto_frame error:%d\n", ret);
					return -1;
				}
				break;
			case 0x02:  // ACK
			case 0x03:  // ACK_ECN
				pr_debug("QUIC ACK frame at offset %zu\n",
				         offset);
				ret = process_ack_frame(data, length, &offset);
				if (ret < 0) {
					pr_debug("process_ack_frame error:%d\n", ret);
					return -1;
				}
				pr_debug("offset after skip ack data:%zu\n", offset);
				break;
			case 0x1c: //CONNECTION_CLOSE
			case 0x1d: //APPLICATION_CLOSE
				pr_debug("QUIC CONNECTION_CLOSE frame at offset %zu\n",
				         offset);
				ret = process_connection_close_frame(data, length, &offset);
				if (ret < 0) {
					pr_debug("process_connection_close_frame error:%d\n", ret);
					return -1;
				}
				is_connection_close = 1;
				pr_debug("offset after skip connection_close data:%zu\n", offset);
				break;

			default:
				pr_debug(
				    "Unexpected QUIC frame type: %02x at "
				    "offset %zu\n",
				    packet_type, offset);
				return -1;
		}
	}

	print_crypto_frame_list(&conv->crypto_frames);

	// check if this is the last CRYPTO frame
	is_frame_complete = is_frame_continuous_and_complete(conv);
	if (is_frame_complete) {
		pr_debug("clienthello complete with this crypto frame.\n");
		// client hello length need to add 4 bytes for the frame type and the length field
		ret = extract_sni(conv->crypto_data,
		                  conv->crypto_frames.client_hello_length + 4,
		                  output_sni, output_sni_len);

		update_conversation_status_and_free_frames(conv, COMPLETE_CLIENT_HELLO);
		if (ret == 0) {
			pr_debug(
			    "sni %s found from the reassembled clienthello.\n",
			    output_sni);
			update_conversation_hostname(conv, output_sni, strlen(output_sni));
			return output_sni_len;
		} else {
			update_conversation_hostname(conv, "", 0);
			pr_debug("QUIC: SNI extraction failed on complete %zu-byte ClientHello\n",
			       conv->crypto_frames.client_hello_length + 4);
			// print_packet_info(&conv->pinfo);
			return -1;
		}
	}

	if (is_connection_close) {
		pr_debug("QUIC CONNECTION_CLOSE frame found, try to remove the conversation\n");
		update_conversation_status_and_free_frames(conv, conv->status);
	}

	pr_debug("all QUIC frames processed, but no sni found, probably a partial initial packet\n");
	return 0;
}

int decrypt_quic_payload(const u8 *key, const u8 *iv, u64 packet_number,
                         const u8 *aad, size_t aad_len, const u8 *ciphertext,
                         size_t ciphertext_len, u8 *output, size_t *output_len,
                         size_t max_output_len) {
	// Construct the nonce
	unsigned char __aligned(ALIGN_SIZE) nonce[16]; // nonce is 12 bytes but we use 16 bytes to align to 16 bytes
	struct quic_cache * cache = NULL;
	int ret;
	int i;

	if (key == NULL || iv == NULL || aad == NULL || ciphertext == NULL ||
	    output == NULL || output_len == NULL) {
		pr_debug("Invalid input pointers\n");
		return -1;
	}

	memcpy(nonce, iv, 12);

	// // nonce[10] ^= (packet_number & 0xff) >> 8;
	// // nonce[11] ^= (packet_number & 0xff);
	for (i = 0; i < 8; i++) {
		nonce[12 - 8 + i] ^= (packet_number >> (8 * (7 - i))) & 0xFF;
	}

	cache = get_quic_cache();

	ret = aes_gcm_decrypt(cache->decrypt_ctx,
	    key, 16, nonce, 12, ciphertext, ciphertext_len, aad,
	    aad_len, output, output_len, max_output_len);
	if (ret != 0) {
		pr_debug("firewalla_gcm_aead_decrypt error:%d, packet_number=%llu\n", ret, packet_number);
		return -1;
	}

	return 0;
}

/* Returns the QUIC draft version or 0 if not applicable. */
static inline uint8_t quic_draft_version(uint32_t version) {
	/* IETF Draft versions */
	if ((version >> 8) == 0xff0000) {
		return (uint8_t)version;
	}
	/* Facebook mvfst, based on draft -22. */
	if (version == 0xfaceb001) {
		return 22;
	}
	/* Facebook mvfst, based on draft -27. */
	if (version == 0xfaceb002 || version == 0xfaceb00e) {
		return 27;
	}
	/* GQUIC Q050, T050 and T051: they are not really based on any drafts,
	 * but we must return a sensible value */
	if (version == 0x51303530 || version == 0x54303530 ||
	    version == 0x54303531) {
		return 27;
	}
	/* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
	   "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
	   forcing version negotiation to be exercised"
	   We can't return a correct draft version because we don't have a real
	   version here! That means that we can't decode any data and we can
	   dissect only the cleartext header. Let's return v1 (any other numbers
	   should be fine, anyway) to only allow the dissection of the
	   (expected) long header */
	if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
		return 34;
	}
	/* QUIC (final?) constants for v1 are defined in draft-33, but draft-34
	   is the final draft version */
	if (version == 0x00000001) {
		return 34;
	}
	/* QUIC Version 2 */
	if (version == 0x6b3343cf) {
		return 100;
	}
	return 0;
}

static inline bool is_quic_draft_max(uint32_t version, uint8_t max_version) {
	uint8_t draft_version = quic_draft_version(version);
	return draft_version && draft_version <= max_version;
}

static inline bool is_quic_v2(uint32_t version) {
	return version == 0x6b3343cf;
}

const u8 *get_initial_salt_for_version(uint32_t version, size_t *salt_len) {
	static const uint8_t handshake_salt_draft_22[20] = {
	    0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
	    0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a};
	static const uint8_t handshake_salt_draft_23[20] = {
	    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
	    0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
	};
	static const uint8_t handshake_salt_draft_29[20] = {
	    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
	    0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
	static const uint8_t handshake_salt_v1[20] = {
	    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
	static const uint8_t hanshake_salt_draft_q50[20] = {
	    0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94,
	    0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45};
	static const uint8_t hanshake_salt_draft_t50[20] = {
	    0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
	    0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10};
	static const int8_t hanshake_salt_draft_t51[20] = {
	    0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
	    0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d};
	static const uint8_t handshake_salt_v2[20] = {
	    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
	    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

	if (version == 0x51303530) {
		*salt_len = sizeof(hanshake_salt_draft_q50);
		return hanshake_salt_draft_q50;
	} else if (version == 0x54303530) {
		*salt_len = sizeof(hanshake_salt_draft_t50);
		return hanshake_salt_draft_t50;
	} else if (version == 0x54303531) {
		*salt_len = sizeof(hanshake_salt_draft_t51);
		return hanshake_salt_draft_t51;
	} else if (is_quic_draft_max(version, 22)) {
		*salt_len = sizeof(handshake_salt_draft_22);
		return handshake_salt_draft_22;
	} else if (is_quic_draft_max(version, 28)) {
		*salt_len = sizeof(handshake_salt_draft_23);
		return handshake_salt_draft_23;
	} else if (is_quic_draft_max(version, 32)) {
		*salt_len = sizeof(handshake_salt_draft_29);
		return handshake_salt_draft_29;
	} else if (is_quic_draft_max(version, 34)) {
		*salt_len = sizeof(handshake_salt_v1);
		return handshake_salt_v1;
	} else if (is_quic_v2(version)) {
		*salt_len = sizeof(handshake_salt_v2);
		return handshake_salt_v2;
	}
	*salt_len = 0;
	return NULL;
}

static void get_labels_for_version(uint32_t version, const char **out_key_label,
                                   const char **out_iv_label,
                                   const char **out_hp_label) {
	static const char key_label_v2[] = "quicv2 key";
	static const char iv_label_v2[] = "quicv2 iv";
	static const char hp_label_v2[] = "quicv2 hp";

	static const char key_label[] = "quic key";
	static const char iv_label[] = "quic iv";
	static const char hp_label[] = "quic hp";

	if (is_quic_v2(version)) {
		*out_key_label = key_label_v2;
		*out_iv_label = iv_label_v2;
		*out_hp_label = hp_label_v2;
	} else {
		*out_key_label = key_label;
		*out_iv_label = iv_label;
		*out_hp_label = hp_label;
	}
}

static int derive_keys(struct quic_header_info *header_info,
                        struct quic_packet_protection_info *o_protection_info) {
	const u8 *initial_salt = NULL;
	size_t salt_len = 0;
	u8 initial_secret[32];  // sha256
	const char client_in_label[] = "client in";
	u8 client_initial_secret[32] = {};
	size_t client_initial_secret_len = sizeof(client_initial_secret);
	const char *key_label = NULL;
	const char *iv_label = NULL;
	const char *hp_label = NULL;
	struct shash_desc *hash = NULL;
	struct quic_cache *cache = NULL;

	int ret;

	// input check
	if (header_info == NULL || o_protection_info == NULL) {
		pr_debug("Invalid input pointers\n");
		return -1;
	}

	cache = get_quic_cache();
	hash = cache->decrypt_ctx->shash;

	initial_salt = get_initial_salt_for_version(header_info->quic_version, &salt_len);
	if (!initial_salt) {
		pr_debug("unsupported quic version:0x%08x\n", header_info->quic_version);
		return -1;
	}

	get_labels_for_version(header_info->quic_version, &key_label, &iv_label, &hp_label);

	ret = hkdf_extract(hash, initial_salt, salt_len, header_info->dcid, header_info->dcid_len,
	                   initial_secret, sizeof(initial_secret));
	if (ret != 0) {
		pr_info("hkdf_extract error:%d\n", ret);
		return -1;
	}

	ret =
	    hkdf_expand_label(hash, initial_secret, sizeof(initial_secret),
	                      client_in_label, strlen(client_in_label),
	                      client_initial_secret, client_initial_secret_len);
	if (ret != 0) {
		pr_err("hkdf_expand_label %s error:%d\n", client_in_label, ret);
		return -1;
	}

	ret = hkdf_expand_label(hash, client_initial_secret,
	                        client_initial_secret_len, key_label,
	                        strlen(key_label), o_protection_info->key, sizeof(o_protection_info->key));
	if (ret != 0) {
		pr_err("hkdf_expand_label %s error:%d\n", key_label, ret);
		return -1;
	}

	ret = hkdf_expand_label(hash, client_initial_secret,
	                        client_initial_secret_len, iv_label,
	                        strlen(iv_label), o_protection_info->iv, sizeof(o_protection_info->iv));
	if (ret != 0) {
		pr_err("hkdf_expand_label %s error:%d\n", iv_label, ret);
		return -1;
	}

	ret = hkdf_expand_label(hash, client_initial_secret,
	                        client_initial_secret_len, hp_label,
	                        strlen(hp_label), o_protection_info->hp_key, sizeof(o_protection_info->hp_key));
	if (ret != 0) {
		pr_err("hkdf_expand_label %s error:%d\n", hp_label, ret);
		return -1;
	}


	return ret;
}

void log_parsed_result(struct packet_info *pinfo, const char *hostname) {
	if (!pinfo) {
		return;
	}
	if (pinfo->family == NFPROTO_IPV4) {
		printk("[FW_QUIC]:{\"src_addr\":\"%pI4\", \"dst_addr\":\"%pI4\", \"src_port\":%u, \"dst_port\":%u, \"protocol\":\"UDP\", \"hostname\":\"%s\"}\n", 
			&pinfo->src_addr, &pinfo->dst_addr, pinfo->src_port, pinfo->dst_port, hostname);
	} else if (pinfo->family == NFPROTO_IPV6) {
		printk("[FW_QUIC]:{\"src_addr\":\"%pI6c\", \"dst_addr\":\"%pI6c\", \"src_port\":%u, \"dst_port\":%u, \"protocol\":\"UDP\", \"hostname\":\"%s\"}\n", 
			&pinfo->src_addr, &pinfo->dst_addr, pinfo->src_port, pinfo->dst_port, hostname);
	}
}


int process_quic_packets(const u_char *payload, size_t payload_length, struct packet_info *pinfo,
	char *output_hostname, size_t output_hostname_len, int *record_hit) {
	int ret = 0;
	size_t offset_of_udp_payload = 0;
	size_t last_offset = 0;
	struct conversation_shard *shard;

	if (payload == NULL || output_hostname == NULL) {
		pr_debug("Invalid input pointers\n");
		return -1;
	}

	// All QUIC packets coalesced into this one datagram share the same 4-tuple, so
	// they share a shard: resolve and lock it once instead of per packet.
	//
	// The lock has to cover the entire loop, not just the lookups. A conversation
	// pointer obtained from the shard is read and mutated all the way through
	// process_quic_frames(), and a concurrent create_conversation() on the same
	// shard can swap an entry out into another CPU's scratch buffer - so a pointer
	// used after unlocking would be touching a buffer that CPU now owns.
	//
	// Hold time is bounded and non-sleeping: the AEAD is synchronous (the tfm is
	// allocated with the CRYPTO_ALG_ASYNC mask, see crypto.c) and crypto_frame_node
	// comes from a kmem_cache with GFP_ATOMIC. And this path only runs for datagrams
	// that carry QUIC Initial packets, i.e. the first one or two of a connection.
	shard = conversation_shard_for(pinfo);
	if (shard)
		conversation_shard_lock(shard);

	while (offset_of_udp_payload < payload_length) {
		ret = process_quic_packet(payload + offset_of_udp_payload, payload_length - offset_of_udp_payload,
			&offset_of_udp_payload, shard, pinfo, output_hostname, output_hostname_len, record_hit);
		if (ret != 0) {
			pr_debug("process_quic_packet error:%d\n", ret);
			goto out;
		}
		if (output_hostname[0] != '\0') {
			pr_debug("found sni:%s\n", output_hostname);
			break;
		}
		if (offset_of_udp_payload <= last_offset) {
			pr_debug(
			    "offset_of_udp_payload wasn't increased something "
			    "might went wrong, offset_of_udp_payload:%zu, "
			    "last_offset:%zu\n",
			    offset_of_udp_payload, last_offset);
			break;
		}
		last_offset = offset_of_udp_payload;
	}
	// Loop finished normally (SNI found, or nothing more to parse): the original
	// code reported success regardless of the last packet's outcome, keep that.
	ret = 0;

out:
	if (shard)
		conversation_shard_unlock(shard);
	return ret;
}

int parse_quic_header(const u_char *payload, size_t payload_length, size_t *o_offset,
	struct quic_header_info *o_header_info) {
	size_t offset = *o_offset;
	u8 packet_type;
	u8 scid_len;
	int64_t token_len; /* must be signed to detect decode_varint errors */
	int64_t quic_payload_len;
	u8 sample[AES_BLOCK_SIZE] = {};
	u8 mask[AES_BLOCK_SIZE];
	u8 mask_byte;
	u8 encrypted_packet_number[4] = {};  // max packet number length is 4 bytes
	u8 pn_length;
	u64 decrypted_pn = 0;
	int ret;
	u8 *associated_data = NULL;
	struct quic_cache *cache = NULL;
	size_t i;
	
	// base on RFC9000, the quic initial packets have UDP
	// payloads of at least 1200 bytes
	size_t minimum_initial_packet_size = 1200;

	if (payload_length < minimum_initial_packet_size) {
		pr_debug("QUIC header too short\n");
		return -1;
	}
	// Check QUIC long header form
	if (!(payload[0] & QUIC_LONG_HEADER_FORM)) {
		pr_debug("Not a QUIC long header packet\n");
		return -1;
	}

	// Extract packet type
	packet_type = (payload[0] & 0x30) >> 4;
	if (packet_type != QUIC_INITIAL_PACKET_TYPE) {
		pr_debug("Not a QUIC Initial packet\n");
		return -1;
	}

	pr_debug("Detected QUIC Initial packet\n");
	offset += 1;  // Skip first byte, current offset is 1

	// Skip version (4 bytes) and connection IDs (variable length)
	o_header_info->quic_version = pntoh32(&payload[offset]);
	offset += 4;  // Skip version, current offset is 5
	pr_debug("quic version:0x%08x\n", o_header_info->quic_version);

	o_header_info->dcid_len = payload[offset];
	pr_debug("dcid len:%0x\n", o_header_info->dcid_len);
	if (o_header_info->dcid_len > 20) {
		pr_debug("dcid_len too long\n");
		return -1;
	}
	offset += 1;  // Skip Destination Connection ID length, current offset is 6

	memcpy(&o_header_info->dcid, &payload[offset], o_header_info->dcid_len);

	pr_debug("dcid:%*phN\n", o_header_info->dcid_len, o_header_info->dcid);
	offset += o_header_info->dcid_len;  // Skip Destination Connection ID, maxium current offset is 26

	scid_len = payload[offset];
	pr_debug("scid_len len:%d\n", scid_len);
	if (scid_len > 20) {
		pr_debug("scid_len too long, dcid:%*phN\n", o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}
	offset += 1 + scid_len;  // Skip Source Connection ID, maxium current offset is 47

	// Handle Token length for Initial packets
	token_len = decode_varint(payload, &offset, payload_length); // token length field is skipped automatically, max 4 bytes
	if (token_len < 0) {
		pr_debug("decode_varint error, failed to get token_len, dcid:%*phN\n", o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}
	if ((size_t)token_len > payload_length - offset) { /* prevent overflow / OOB */
		pr_debug("token_len too large: %lld (remain:%zu), dcid:%*phN\n", token_len, payload_length - offset, o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}
	pr_debug("token_len len:%0lld, offset after token_len:%zu\n", (unsigned long long)token_len, offset);

	offset += token_len;  // Skip Token, maximum current offset is 51+token_len
	if (offset >= payload_length) {
		pr_debug("Packet truncated before payload, offset:%zu, payload_length:%zu, dcid:%*phN\n", offset, payload_length, o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}

	// Handle Length field
	// Decode Length field (QUIC uses variable-length integers)
	// The length includes both the Packet Number and Payload fields
	// skip length field, maxium current offset is 55+token_len
	quic_payload_len = decode_varint(payload, &offset, payload_length);
	if (quic_payload_len < 0) {
		pr_debug("decode_varint error, dcid:%*phN\n", o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}

	pr_debug("quic payload_len:%llu\n", (unsigned long long)quic_payload_len);
	if (quic_payload_len > get_max_MTU()) {  // payload length should not exceed MTU
		pr_debug("quic_payload_len too long, dcid:%*phN\n", o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}
	o_header_info->payload_len = (u32)quic_payload_len;

	if (offset + 4 + AES_BLOCK_SIZE > payload_length) {
		pr_debug("Packet truncated before sample, dcid:%*phN\n", o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}

	memcpy(sample, payload + offset + 4, AES_BLOCK_SIZE);

	cache = get_quic_cache();

	// Reuse cached keys when DCID and version match, avoiding repeated HKDF
	// derivation. Scans KEY_CACHE_SIZE entries rather than a single slot so that
	// several concurrently-handshaking connections on this CPU each keep their own
	// derived key instead of evicting one another every packet.
	{
		struct key_cache *kc = &cache->key_cache;
		struct key_cache_entry *slot = NULL;

		for (i = 0; i < KEY_CACHE_SIZE; i++) {
			struct key_cache_entry *e = &kc->entries[i];
			if (e->valid && e->dcid_len == o_header_info->dcid_len &&
			    e->quic_version == o_header_info->quic_version &&
			    memcmp(e->dcid, o_header_info->dcid, o_header_info->dcid_len) == 0) {
				pr_debug("key_cache hit, skip derive_keys\n");
				slot = e;
				break;
			}
		}

		if (!slot) {
			slot = &kc->entries[kc->next];
			kc->next = (kc->next + 1) % KEY_CACHE_SIZE;

			ret = derive_keys(o_header_info, &slot->protection_info);
			if (ret != 0) {
				slot->valid = false;
				pr_debug("derive_keys error:%d, dcid:%*phN\n", ret, o_header_info->dcid_len, o_header_info->dcid);
				return -1;
			}
			slot->valid = true;
			slot->dcid_len = o_header_info->dcid_len;
			slot->quic_version = o_header_info->quic_version;
			memcpy(slot->dcid, o_header_info->dcid, o_header_info->dcid_len);
		}

		o_header_info->protection_info = &slot->protection_info;
	}

	aes_ecb_encrypt(o_header_info->protection_info->hp_key,
	                sizeof(o_header_info->protection_info->hp_key), sample, mask);

	mask_byte = mask[0];
	pr_debug("mask_byte:%02x\n", mask_byte);

	associated_data = cache->decrypt_ctx->aad_data_buf;
	// get associated data, starting from the first byte of either the short or long header,
	// up to and including the unprotected packet number.
	// 4 bytes for packet number, maxium assoicated data length is 59+token_len bytes
	if (offset > get_max_MTU()) { /* associated data shouldn't exceed MTU sized buffer we allocated */
		pr_debug("associated data length exceeds max MTU: offset=%zu, max=%u, dcid:%*phN\n", offset, get_max_MTU(), o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}
	memcpy(associated_data, payload, offset);
	associated_data[0] ^= mask_byte & 0x0f;

	o_header_info->packet_number_len = (associated_data[0] & 0x03) + 1;  // get real packet number length from the unprotected header
	pr_debug("packet_number_len:%d\n", o_header_info->packet_number_len);
	if (o_header_info->packet_number_len > 4) {
		pr_debug("packet_number_len too long, dcid:%*phN\n", o_header_info->dcid_len, o_header_info->dcid);
		return -1;
	}

	pr_debug("offset before add offset for packet number:%zu\n", offset);
	pr_debug("packet number len:%d\n", o_header_info->packet_number_len);

	memcpy(encrypted_packet_number, &payload[offset], o_header_info->packet_number_len);

	pr_debug("encrypted_packet_number:%*phN\n", o_header_info->packet_number_len, encrypted_packet_number);

	if (offset >= payload_length) {
		pr_debug("Packet truncated before payload\n");
		return -1;
	}

	pn_length = o_header_info->packet_number_len;
	for (i = 0; pn_length > 0; pn_length--, i++) {
		u8 tmp = 0;
		tmp = encrypted_packet_number[i];
		decrypted_pn |= (tmp ^ mask[i + 1]) << (8 * (pn_length - 1));
	}

	pr_debug("decrypted packet num:%llu\n", decrypted_pn);
	o_header_info->packet_number = decrypted_pn;

	pr_debug("associated_data[0]:%02x\n", associated_data[0]);
	for (i=0; i<o_header_info->packet_number_len; i++) {
		associated_data[offset + o_header_info->packet_number_len - 1 - i] = (uint8_t)(decrypted_pn >> (8 * i));
	}

	pr_debug("payload[offset]:%02x\n", payload[offset]);
	*o_offset = offset;
	
	return 0;
}

int process_quic_packet(const u_char *payload, size_t payload_length, size_t *offset_of_udp_payload,
	struct conversation_shard *shard, struct packet_info *pinfo,
			char *output_hostname, size_t output_hostname_len, int *record_hit) {
	size_t offset = 0;
	u16 remain_length;


	const u8 *quic_payload = NULL;
	u8 *associated_data = NULL;
	u8 *decrypted_quic_payload = NULL;
	struct quic_cache *cache = NULL;
	struct conversation *conv = NULL;
	struct quic_packet_protection_info *protection_info;
	int ret;

	// parse quic header
	struct quic_header_info header_info = {0};

	cache = get_quic_cache();

	// print_packet_info(pinfo);

	if (parse_quic_header(payload, payload_length, &offset, &header_info) != 0) {
		pr_debug("parse_quic_header error\n");
		return -1;
	}
	// Set by parse_quic_header() to the key_cache entry (hit or freshly derived)
	// matching this packet's DCID - not a fixed field any more now that key_cache
	// holds several entries.
	protection_info = header_info.protection_info;
	if (!protection_info) {
		pr_debug("no protection_info resolved for this packet\n");
		return -1;
	}

	// Complete the cache key with this packet's DCID before any lookup, so state
	// left by an earlier connection on the same 4-tuple is never reused.
	// parse_quic_header() has already bounded dcid_len to 20.
	pinfo->dcid_len = header_info.dcid_len;
	memcpy(pinfo->dcid, header_info.dcid, header_info.dcid_len);

	// Same packet re-evaluated by a subsequent iptables rule: skip redundant parsing
	if (//cache->last_pkt.valid &&
	    compare_packet_info(&cache->last_pkt.pinfo, pinfo) == 0 &&
	    cache->last_pkt.packet_number == header_info.packet_number) {
		pr_debug("packet already processed by a previous rule, reusing cached result\n");
		*offset_of_udp_payload += payload_length;
		if (cache->last_pkt.hostname[0] != '\0') {
			strncpy(output_hostname, cache->last_pkt.hostname, cache->last_pkt.hostname_len);
			*record_hit = 1;
			return 0;
		}
		pr_debug("packet already processed by a previous rule, dcid:%*phN\n", header_info.dcid_len, header_info.dcid);
		return -1;
	}

	// shard is already locked by process_quic_packets(), and stays locked for the
	// whole of this function - conv is mutated by process_quic_frames() below.
	conv = shard ? find_conversation(shard, pinfo) : NULL;
	if (conv) {
		if (conv->status == ERROR) {
			pr_debug("conversation error, drop the packet\n");
			return -1;
		} else if (conv->status == COMPLETE_CLIENT_HELLO) {
			*offset_of_udp_payload += payload_length;
			// cache->last_pkt.valid = true;
			memcpy(&cache->last_pkt.pinfo, pinfo, sizeof(struct packet_info));
			cache->last_pkt.packet_number = header_info.packet_number;
			if (conv->hostname[0] == '\0') {
				pr_debug("QUIC: conversation complete but SNI empty - connection missed\n");
				cache->last_pkt.hostname[0] = '\0';
				cache->last_pkt.hostname_len = 0;
				*record_hit = 0;
				return -1;
			}
			pr_debug("conversation already complete, return sni directly, sni:%s\n", conv->hostname);
			// Same packet evaluated by multiple iptables rules: restore record_hit
			// so each matching rule can count the hit exactly once per connection.
			if (header_info.packet_number == conv->completing_packet_number)
				*record_hit = 1;
			strncpy(output_hostname, conv->hostname, conv->hostname_len);
			memcpy(cache->last_pkt.hostname, conv->hostname, conv->hostname_len);
			cache->last_pkt.hostname[conv->hostname_len] = '\0';
			cache->last_pkt.hostname_len = conv->hostname_len;
			return 0;
		}
	}

	associated_data = cache->decrypt_ctx->aad_data_buf;

	// Remaining is payload
	remain_length = payload_length - offset;
	if (remain_length < header_info.payload_len) {
		pr_debug(
		    "Packet truncated before payload, remain_length:%d, "
		    "quic_payload_len:%llu\n",
		    remain_length, (unsigned long long)header_info.payload_len);
		return -1;
	}
	quic_payload = payload + offset + header_info.packet_number_len;

	pr_debug("Extracted QUIC payload of length: %llu, dcid:%*phN\n", (unsigned long long)header_info.payload_len, header_info.dcid_len, header_info.dcid);

	// decrypted payload length should be encrypted payload lenght - tag length(16 bytes)
	// and less than the maximum MTU
	decrypted_quic_payload = cache->decrypt_ctx->plain_text;

	if (header_info.payload_len > 0) {
		size_t decrypted_payload_len;

		pr_debug("QUIC payload detected\n");

		// decrypt QUIC payload
		pr_debug("quic_payload[0]:%02x\n", quic_payload[0]);
		if (header_info.payload_len < header_info.packet_number_len + 16) {
			pr_debug("QUIC payload too short\n");
			return -1;
		}

		ret = decrypt_quic_payload(
		    protection_info->key, protection_info->iv, header_info.packet_number, associated_data,
		    offset + header_info.packet_number_len, quic_payload,
		    header_info.payload_len - header_info.packet_number_len,
		    decrypted_quic_payload, &decrypted_payload_len,
		    payload_length);
		if (ret != 0) {
			// pr_debug("decrypt_quic_payload error:%d\n", ret);
			if (pinfo->family == NFPROTO_IPV4) {
				pr_debug("decrypt_quic_payload error:%d saddr=%pI4, dstaddr=%pI4, sport=%u, dport=%u\n", ret,
					&pinfo->src_addr, &pinfo->dst_addr, pinfo->src_port, pinfo->dst_port);
			} else if (pinfo->family == NFPROTO_IPV6) {
				pr_debug("decrypt_quic_payload error:%d saddr=%pI6c, dstaddr=%pI6c, sport=%u, dport=%u\n", ret,
					&pinfo->src_addr, &pinfo->dst_addr, pinfo->src_port, pinfo->dst_port);
			}
			return -1;
		}
		pr_debug("decrypt success.\n");
		*offset_of_udp_payload += offset + header_info.payload_len;

		// When there is no existing conversation, use the per-CPU scratch buffer to
		// accumulate CRYPTO frames for this packet.  A ring buffer slot is only
		// reserved if the ClientHello turns out to be incomplete within this packet.
		if (conv == NULL) {
			struct conversation *scratch = cache->scratch_conv;
			reset_conversation(scratch);
			memcpy(&scratch->pinfo, pinfo, sizeof(struct packet_info));
			conv = scratch;
		}

		ret = process_quic_frames(decrypted_quic_payload,
		                          decrypted_payload_len, conv, pinfo,
		                          output_hostname, output_hostname_len);
		if (ret < 0) {
			if (conv == cache->scratch_conv)
				reset_conversation(conv);
			pr_debug("process_quic_frames error:%d\n", ret);
			return -1;
		}
		ret = 0;


		// If the scratch was used and the ClientHello is still incomplete after this
		// packet, promote to a ring buffer slot by swapping scratch_conv with the
		// ring buffer pointer so subsequent packets find it via find_conversation().
		if (shard && conv == cache->scratch_conv &&
		    output_hostname[0] == '\0' && conv->crypto_frames.head != NULL && is_first_crypto_frame_included(conv)) {
			conv = create_conversation(shard, pinfo, &cache->scratch_conv);
			if (conv == NULL) {
				reset_conversation(cache->scratch_conv);
				// cache->last_pkt.valid = false;
				return -1;
			}
		}

		if (conv) {
			conv->completing_packet_number = header_info.packet_number;
			if (conv->hostname_len > 0) {
				// Complete with SNI (either from scratch or ring buffer conversation):
				// cache for multi-rule re-evaluation of this same packet.
				// cache->last_pkt.valid = true;
				memcpy(&cache->last_pkt.pinfo, pinfo, sizeof(struct packet_info));
				cache->last_pkt.packet_number = header_info.packet_number;
				memcpy(cache->last_pkt.hostname, conv->hostname, conv->hostname_len);
				cache->last_pkt.hostname[conv->hostname_len] = '\0';
				cache->last_pkt.hostname_len = conv->hostname_len;
				*record_hit = 1;
			} else {
				// Still incomplete: invalidate so port-reuse connections are not
				// blocked by this stale cache entry.
				// cache->last_pkt.valid = false;
			}
		}
	} else {
		pr_debug("No QUIC payload found\n");
		ret = -1;
	}

	return ret;
}

int quic_parser_test() {
	u8 test_dcid[] = {0x25, 0x32, 0x9b, 0x62, 0x73, 0x52, 0xbe, 0x53};
	u8 initial_secret[32] = {};
	u8 client_secret[32] = {};
	u8 hp[16] = {};
	u8 key[16] = {};
	u8 iv[12] = {};
	u8 sample[] = {0x6c, 0x38, 0x4d, 0x6f, 0x7d, 0x78, 0x7c, 0xac,
	               0xfa, 0x5f, 0xda, 0x82, 0xe1, 0x88, 0x50, 0xb7};

	u8 mask[16] = {};
	char hostname[256] = {};
	char expected_hostname[] = "www.youtube.com";

	int ret;
	u8 client_in_label[MAX_LABEL_LENGTH] = {};
	size_t client_in_label_len;
	u8 hp_label[MAX_LABEL_LENGTH] = {};
	size_t hp_label_len;
	u8 quic_key_label[MAX_LABEL_LENGTH] = {};
	size_t key_label_len;
	u8 quic_iv_label[MAX_LABEL_LENGTH] = {};
	size_t iv_label_len;
	struct shash_desc *hash = NULL;
	struct packet_info pinfo = {};
	int record_hit = 0;
	
	pr_info("self test start, perfroming quic decryption test\n");
	pr_debug("load initial secret\n");
	pinfo.src_port = 65535;
	pinfo.dst_port = 65535;

	hash = alloc_hash_sha256();
	if (!hash) {
		pr_err("alloc_hash_sha256 error\n");
		return -1;
	}

	ret = hkdf_extract(hash, INITIAL_SALT, sizeof(INITIAL_SALT), test_dcid,
	                   sizeof(test_dcid), initial_secret,
	                   sizeof(initial_secret));
	if (ret != 0) {
		pr_info("hkdf_extract error:%d\n", ret);
		goto out_free_hash;
	}
	print_hex("initial secret", initial_secret, sizeof(initial_secret));
	pr_debug("load initial secret done\n");

	ret = build_label(client_in_label, sizeof(client_in_label), 32,
	                  "client in", strlen("client in"));
	if (ret < 0) {
		pr_err("build_label failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("client in label", client_in_label, ret);
	client_in_label_len = ret;

	ret = build_label(hp_label, sizeof(hp_label), 16, "quic hp",
	                  strlen("quic hp"));
	if (ret < 0) {
		pr_err("build_label failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("hp label", hp_label, ret);
	hp_label_len = ret;

	ret = build_label(quic_key_label, sizeof(quic_key_label), 16,
	                  "quic key", strlen("quic key"));
	print_hex("quic key label", quic_key_label, ret);
	key_label_len = ret;

	ret = build_label(quic_iv_label, sizeof(quic_iv_label), 12, "quic iv",
	                  strlen("quic iv"));
	if (ret < 0) {
		pr_err("build_label failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("quic iv label", quic_iv_label, ret);
	iv_label_len = ret;

	ret = hkdf_expand(hash, initial_secret, sizeof(initial_secret),
	                  client_in_label, client_in_label_len, client_secret,
	                  sizeof(client_secret));
	if (ret) {
		pr_err("hkdf_expand failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("client secret", client_secret, sizeof(client_secret));

	ret = hkdf_expand(hash, client_secret, sizeof(client_secret),
	                  quic_key_label, key_label_len, key, sizeof(key));
	if (ret) {
		pr_err("hkdf_expand failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("key", key, sizeof(key));

	ret = hkdf_expand(hash, client_secret, sizeof(client_secret),
	                  quic_iv_label, iv_label_len, iv, sizeof(iv));
	if (ret) {
		pr_err("hkdf_expand failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("iv", iv, sizeof(iv));

	ret = hkdf_expand(hash, client_secret, sizeof(client_secret), hp_label,
	                  hp_label_len, hp, sizeof(hp));
	if (ret) {
		pr_err("hkdf_expand failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("hp", hp, sizeof(hp));

	ret = aes_ecb_encrypt(hp, sizeof(hp), sample, mask);
	if (ret) {
		pr_err("aes_ecb_encrypt failed with error %d\n", ret);
		goto out_free_hash;
	}
	print_hex("mask", mask, 16);

	ret =
	    process_quic_packets(SAMPLE_QUIC_PACKET, sizeof(SAMPLE_QUIC_PACKET), &pinfo,
	                        hostname, sizeof(hostname), &record_hit);
	if (ret < 0) {
		pr_debug("process_quic_packet failed with error %d\n", ret);
		goto out_free_hash;
	}
	if (strlen(hostname) != strlen(expected_hostname) ||
	    strncmp(hostname, expected_hostname, strlen(expected_hostname))) {
		pr_err(
		    "process_quic_packet failed, got unexpected hostname:%s, "
		    "expected:%s\n",
		    hostname, expected_hostname);
		ret = -1;
		goto out_free_hash;
	}
	pr_info("self test passed\n");
	ret = 0;

out_free_hash:
	free_hash_sha256(hash);
	return ret;
}