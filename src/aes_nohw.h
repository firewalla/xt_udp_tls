/* Copyright (c) 2019, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef _AES_NOHW_H_
#define _AES_NOHW_H_

#include <linux/types.h>

#define AES_MAXNR 14

struct aes_key_st {
  u32 rd_key[4 * (AES_MAXNR + 1)];
  unsigned rounds;
};


typedef struct aes_key_st AES_KEY;



int aes_nohw_set_encrypt_key(const u8 *key, unsigned bits,
                             AES_KEY *aeskey);
void aes_nohw_encrypt(const u8 *in, u8 *out, const AES_KEY *key);



#endif /* _AES_NOHW_H_ */