/**
 * Copyright (c) 2016, David J. Wu, Kevin Lewi, with changes (2019) by Gunnar Hartung.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "errors.h"
#include "flags.h"

#include <openssl/evp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

// #define AES_BLOCK_LEN 16
static const int AES_KEY_BYTES       = 16;
static const int AES_BLOCK_LEN       = 16;
static const int AES_OUTPUT_BYTES    = 16;
static const int SHA256_OUTPUT_BYTES = 32;

typedef unsigned char byte;
typedef union {
  byte bytes[AES_BLOCK_LEN];
  uint16_t shorts[AES_BLOCK_LEN / sizeof(uint16_t)];
  uint32_t words[AES_BLOCK_LEN / sizeof(uint32_t)];
  uint64_t longs[AES_BLOCK_LEN / sizeof(uint64_t)];
} block;

static inline void pack_block(uint64_t x, uint64_t y, block* blk) {
  // I'm converting to network byte order
  blk->words[0] = htonl(x >> 32);
  blk->words[1] = htonl(x & 0xFFFFFFFF);
  blk->words[2] = htonl(y >> 32);
  blk->words[3] = htonl(y & 0xFFFFFFFF);
}

static inline void unpack_block(const block* blk, uint64_t* x, uint64_t* y) {
  *x = ((uint64_t) ntohl(blk->words[0])) << 32 | ntohl(blk->words[1]);
  *y = ((uint64_t) ntohl(blk->words[2])) << 32 | ntohl(blk->words[3]);
}

typedef struct {
  EVP_CIPHER_CTX* cipher_ctx;
} AES_KEY;

// Structure representing a PRF key and output size of PRF.
#ifdef USE_AES

typedef struct {
  AES_KEY key;
} prf_key[1];

static const int PRF_INPUT_BYTES  = 16;
static const int PRF_OUTPUT_BYTES = 16;

#else

typedef struct {
  byte keybuf[32];
} prf_key[1];

static const int PRF_OUTPUT_BYTES = 32;

#endif

/**
 * Reads from /dev/urandom to sample a PRF key.
 *
 * @param key The PRF key to construct
 *
 * @return ERROR_NONE on success and ERROR_RANDOMNESS if reading
 * from /dev/urandom failed.
 */
int generate_prf_key(prf_key key);

/**
 * Evaluates the PRF given a key and input (as byte arrays), storing
 * the result in a destination byte array.
 *
 * @param dst    The destination byte array that will contain the output of the PRF
 * @param dstlen The size of the destination byte array
 * @param key    The PRF key
 * @param src    The byte array containing the input to the PRF
 * @param srclen The size of the input byte array
 *
 * @return ERROR_NONE on success, ERROR_DSTLEN_INVALID if the destination size
 *         is invalid
 */
int prf_eval(byte* dst, uint32_t dstlen, prf_key key, byte* src, uint32_t srclen);

/**
 * frees memory associated with the given prf_key.
 *
 * @param key The PRF key to be freed.
 *
 * @return ERROR_NONE on success
 */
int free_prf_key(prf_key key);


/*****************************************************************************
 * Most of the functions below are only used for the more complex ORE scheme *
 * described in this paper: "Order-Revealing Encryption: New Constructions,  *
 * Applications, and Lower Bounds" (http://eprint.iacr.org/2016/612.pdf)     *
 *****************************************************************************/


/**
 * Initializes the given AES key instance with a fresh, random key.
 *
 * @param key  The sampled AES key
 *
 * @return ERROR_NONE on success and ERROR_RANDOMNESS if acquiring of
 * the required random data failed.
 */
int generate_aes_key(AES_KEY* key);

/**
 * Initializes the AES key (e.g., derive the round keys).
 *
 * @param key     The initialized AES key (output)
 * @param buf     The AES key to initialize
 * @param buflen  Length of the key buffer
 *
 * @return ERROR_NONE on success and ERROR_PRF_KEYLEN_INVALID if buffer has
 *         the wrong length
 */
int setup_aes_key(AES_KEY* key, byte* buf, uint32_t buflen);

/**
 * Evaluates AES(k, x) on a single block x.
 *
 * @param dst    The input block x that will be overwritten with AES(k, x)
 * @param key    The AES key k
 *
 * @return ERROR_NONE on success
 */
static inline int aes_eval_in_place(block* dst, const AES_KEY* key) {
  block buffer;
  int outl;
  int result = EVP_EncryptUpdate(key->cipher_ctx, buffer.bytes, &outl, dst->bytes, sizeof(dst->bytes));
  if (result == 1 && outl == sizeof(buffer.bytes)) {
    memcpy(dst->bytes, buffer.bytes, sizeof(buffer.bytes));
    return ERROR_NONE;
  } else {
    return ERROR_ENCRYPT;
  };
}

/**
 * Evaluates AES(k, x) on a single block x.
 *
 * @param dst    The destination block that will contain the output of AES
 * @param key    The AES key k
 * @param src    The value x on which to evaluate AES
 *
 * @return ERROR_NONE on success
 */
static inline int aes_eval(block* dst, const AES_KEY* key, const block src) {
  *dst = src;
  return aes_eval_in_place(dst, key);
}

/**
 * Evaluates AES on multiple blocks (with the same underlying key)
 *
 * @param dst      A vector of blocks (of length nblocks) that will contain the
 *                 outputs of AES
 * @param nblocks  The number of input/output blocks
 * @param key      The AES key k
 * @param src      A vector of blocks (of length nblocks) on which to evaluate AES
 *
 * @return ERROR_NONE on success
 */
static inline int aes_eval_blocks(block* dst, uint32_t nblocks, const AES_KEY* key, const block* src) {

  int outl;
  if (nblocks * AES_BLOCK_LEN < nblocks) {
    return ERROR_OVERFLOW;
  };

  int result = EVP_EncryptUpdate(key->cipher_ctx, dst->bytes, &outl, src->bytes, nblocks * AES_BLOCK_LEN);
  if (result == 1 && outl == nblocks * AES_BLOCK_LEN) {
    return ERROR_NONE;
  } else {
    return ERROR_ENCRYPT;
  };
}

/**
 * frees memory associated with the given AES key.
 *
 * @param key the key to be de-initialized
 *
 * @return ERROR_NONE on success
 */
int free_aes_key(AES_KEY * key);

/**
 * Evaluates SHA-256 on an input value.
 *
 * @param dst     A buffer that will hold the outputs of SHA-256
 * @param dstlen  The size of the output buffer
 * @param src     The input to SHA-256
 * @param nbits   The size of the input buffer
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
*/
int sha_256(byte* dst, uint32_t dstlen, byte* src, uint32_t srclen);


/**
 * Seeds the PRG with fresh randomness obtained from a secure source.
 *
 * It is not necessary to call this function before obtaining data from
 * the PRG with next_prg_block(), next_prg_block() will initialize this
 * PRG if necessary.
 *
 * It is possible, however, to call this function. In this case,
 * new seed data will be obtained and the PRG will be re-initialized.
 *
 * If this function returns an error, the PRG must not be used until it
 * has been seeded without an error.
 *
 * @return ERROR_NONE on success, or an error value indicating what went wrong.
 */
int seed_prg();


/**
 * Gets the next block (16 bytes) of output from the PRG.
 *
 * The PRG implemented here is for demo purposes only. For concrete applications,
 * it may be preferable to use a different source for the encryption
 * randomness and key generation.
 *
 * In particular, this PRG implementation is NOT thread-
 * safe, so this library should not be used as is in a multi-threaded
 * execution environment.
 *
 * @param out  Buffer that will hold the next block of the PRG
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
int next_prg_block(block* out);


/**
 * Performs AES-128-GCM encryption with authenticated data.
 *
 * This function uses four output parameters, one of which acts as an input parameter as well:
 * * the IV buffer iv
 * * the ciphertext buffer ctxt_buffer
 * * the ciphertext buffer length ctxt_buffer_len
 * * the authentication tag buffer auth_tag_buf
 *
 * The ciphertext buffer length is an input- and output parameter.
 * As input parameter, it specifies the amount of available bytes in the ciphertext buffer.
 * As output parameter, it will be set to the length of the resulting ciphertext.
 *
 * This function does not consider the IV or the authentication tag to be part of the ciphertext.
 * The ciphertext only contains the encrypted plaintext.
 *
 *
 * @param key              The AES key to use, of key_length bytes.
 * @param key_length       The length of the AES key. Currently only AES-128 is implemented,
 *                         so key_length must be set to 16.
 * @param auth_data        Data that will be authenticated (i.e. it will be checked
 *                         for modifications during decryption), but not encrypted.
 * @param auth_data_len    The amount of data (in bytes) to be authenticated but not encrypted.
 * @param ptxt             A pointer to a buffer of data that will be encrypted (and authenticated).
 * @param ptxt_len         The amount of data (in bytes) to encrypt.
 * @param iv               A pointer to an initialization vector. The data pointed to needs not be
 *                         initialized. This function will choose a fresh IV and write it to *iv.
 * @param iv_len           The length of the IV. Currently must be 16.
 * @param ctxt_buffer      A pointer to a buffer where the ciphertext will be stored.
 *                         The buffer must be large enough to hold the ciphertext.
 *                         (For GCM, the ciphertext will have the same length as the plaintext.)
 * @param ctxt_buffer_len  When calling this function, this pointer must point to integer holding
 *                         the length of the allocated ctxt_buffer.
 *                         This function will overwrite the integer pointed to with the length of
 *                         the resulting ciphertext.
 * @param auth_tag_buf     A pointer to a buffer (of auth_tag_len bytes) that will hold the GCM
 *                         authentication tag.
 * @param auth_tag_len     The length (in bytes) of the auth_tag buffer. Currently must be 16.

 *
 * @return ERROR_NONE on success, and a corresponding error code on failure.
 */
int aes_gcm_encrypt(
        const byte * key, int key_length,
        const byte* auth_data, int auth_data_len,
        const byte* ptxt, int ptxt_len,
        block* iv, int iv_len,
        byte* ctxt_buffer, uint32_t* ctxt_buffer_len,
        block* auth_tag_buf, uint32_t auth_tag_len
);

/**
 * Performs AES-128-GCM decryption with authenticated data.
 *
 * The decryption operation will check that the authenticated data, the ciphertext,
 * the IV and the auth tag have not been modified. An error is returned if a modification
 * has been detected.
 * (If auth data different from the auth data used for encryption is passed to this function,
 * an error will be returned.)
 *
 * This function uses two output parameters, one of which acts as an input parameter as well:
 * * the plaintext buffer ptxt_buffer
 * * the plaintext buffer length ptxt_buffer_len
 *
 * The plaintext buffer length is an input- and output parameter.
 * As input parameter, it specifies the amount of available bytes in the plaintext buffer.
 * As output parameter, it will be set to the length of the resulting plaintext.
 *
 * This function does not consider the IV or the authentication tag to be part of the ciphertext.
 * The ciphertext only contains the encrypted plaintext.
 *
 *
 * @param key              The AES key to use, of key_length bytes.
 * @param key_length       The length of the AES key. Currently only AES-128 is implemented,
 *                         so key_length must be set to 16.
 * @param auth_data        Data that will be checked for modifications. If this is the same data
 *                         that has been passed to the encryption procedure and the ciphertext, IV and auth tag
 *                         have not been modified, then the decryption should succeed.
 * @param auth_data_len    The amount of data (in bytes) to be checked for modifications.
 * @param ctxt             A pointer to the ciphertext to be decrypted (and checked for modifications).
 * @param ctxt_len         The length (in bytes) of the ciphertext.
 * @param iv               A pointer to the initialization vector used during encryption.
 * @param iv_len           The length of the IV. Currently must be 16.
 * @param ptxt_buffer      A pointer to a buffer where the plaintext will be stored.
 *                         The buffer must be large enough to hold the plaintext.
 *                         (For GCM, the plaintext will have the same length as the ciphertext.)
 * @param ptxt_buffer_len  When calling this function, this pointer must point to an integer holding
 *                         the length of the allocated ptxt_buffer.
 *                         This function will overwrite the integer pointed to with the length of
 *                         the plaintext.
 * @param auth_tag_buf     A pointer to a buffer (of auth_tag_len bytes) that holds the GCM
 *                         authentication tag created during encryption.
 * @param auth_tag_len     The length (in bytes) of the auth_tag buffer. Currently must be 16.
 *
 * @return ERROR_NONE on success, and a corresponding error code on failure.
 */
int aes_gcm_decrypt(
        const byte * key, int key_length,
        const byte* auth_data, int auth_data_len,
	const byte* ctxt, int ctxt_len,
	const block* iv, int iv_len,
	byte* ptxt_buffer, uint32_t* ptxt_buffer_len,
	const block* auth_tag_buf, uint32_t auth_tag_len
);

#endif /* __CRYPTO_H__ */
