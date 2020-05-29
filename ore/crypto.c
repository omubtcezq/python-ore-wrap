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

#include "crypto.h"
#include "errors.h"

#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>

// Helper macro for error handling
static int _error_flag;
#define ERR_CHECK(x) if((_error_flag = x) != ERROR_NONE) { return _error_flag; }
#define ERR_CHECK_CLEANUP(x, cleanup_code) if((_error_flag = x) != ERROR_NONE) { cleanup_code; return _error_flag; }
#define ERR_CHECK_EVP_CLEANUP(x, error_code, cleanup_code) if((_error_flag = x) != 1) {cleanup_code; return error_code; }

// Provide a simple random number generator.
// The PRG is implemented using AES in counter mode.
// This implementation is for demo purposes _only_. It is not thread-safe,
// does not re-initialize on fork(), and probably has a lot more problems.
static bool _prg_initialized = false;
static uint64_t _counter = 0;
static AES_KEY _prg_key;


int generate_prf_key(prf_key key) {
#ifdef USE_AES
  return generate_aes_key(&key->key);
#else
  FILE* f = fopen("/dev/urandom", "r");
  if (f == NULL) {
    return ERROR_RANDOMNESS;
  }

  int bytes_read = fread(key->keybuf, 1, sizeof(key->keybuf), f);
  if (bytes_read != sizeof(key->keybuf)) {
    return ERROR_RANDOMNESS;
  }

  fclose(f);

  return ERROR_NONE;
#endif
}


int prf_eval(byte* dst, uint32_t dstlen, prf_key key, byte* src, uint32_t srclen) {
  if (dstlen != PRF_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

#ifdef USE_AES
  if (srclen != PRF_INPUT_BYTES) {
    return ERROR_SRCLEN_INVALID;
  }
  block* dst_blk = (block*) dst;
  block* src_blk = (block*) src;

  return aes_eval(dst_blk, &key->key, *src_blk);
#else
  uint32_t outlen;
  HMAC(EVP_sha256(), key->keybuf, sizeof(key->keybuf), src, srclen, dst, &outlen);
  assert(outlen == dstlen);

  return ERROR_NONE;
#endif
}


int free_prf_key(prf_key key) {
#ifdef USE_AES
  free_aes_key(&(key->key));
#else
  // nothing to do here
#endif
};

int generate_aes_key(AES_KEY* key) {
  byte keybuf[AES_KEY_BYTES];

  int result = RAND_priv_bytes(keybuf, AES_KEY_BYTES);
  if (result != 1) {
    return ERROR_RANDOMNESS;
  }

  return setup_aes_key(key, keybuf, sizeof(keybuf));

  // // FILE* f = fopen("/dev/urandom", "r");
  // FILE *f = fopen("C:\\Projekte\\SeReMo\\seremo\\Spikes\\NodeOre\\package-lock.json", "r");
  // if (f == NULL) {
  //   return ERROR_RANDOMNESS;
  // }

  // int bytes_read = fread(keybuf, 1, AES_KEY_BYTES, f);
  // if (bytes_read != AES_KEY_BYTES) {
  //   return ERROR_RANDOMNESS;
  // }

  // fclose(f);

}

int setup_aes_key(AES_KEY* key, byte* buf, uint32_t buflen) {
  if (buflen != AES_KEY_BYTES) {
    return ERROR_PRF_KEYLEN_INVALID;
  }

  key->cipher_ctx = EVP_CIPHER_CTX_new();
  if (key->cipher_ctx == NULL) {
    // probably not 100% precise, but close enough
    return ERROR_MEMORY_ALLOCATION;
  };

  int result = EVP_EncryptInit_ex(key->cipher_ctx, EVP_aes_128_ecb(), NULL, buf, NULL);
  if (result == 1) {
    return ERROR_NONE;
  } else {
    EVP_CIPHER_CTX_free(key->cipher_ctx);
    key->cipher_ctx = NULL;
    return ERROR_KEY_SETUP;
  };

}

int free_aes_key(AES_KEY * key) {
  if (key->cipher_ctx == NULL) {
    return ERROR_SK_NOT_INITIALIZED;
  };
  EVP_CIPHER_CTX_free(key->cipher_ctx);
  key->cipher_ctx = NULL;
  return ERROR_NONE;
};



int sha_256(byte* dst, uint32_t dstlen, byte* src, uint32_t srclen) {
  if (dstlen != SHA256_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, src, srclen);
  SHA256_Final(dst, &ctx);

  return ERROR_NONE;
}


int seed_prg() {
  ERR_CHECK(generate_aes_key(&_prg_key));
  _counter = 0;
  _prg_initialized = true;
  return ERROR_NONE;
}

int next_prg_block(block* out) {
  if (!_prg_initialized) {
    ERR_CHECK(seed_prg());
  };
  pack_block(0, _counter++, out);
  return aes_eval_in_place(out, &_prg_key);
}


int aes_gcm_encrypt(
        const byte * key, int key_length,
        const byte* auth_data, int auth_data_len,
        const byte* ptxt, int ptxt_len,
        block* iv, int iv_len,
        byte* ctxt_buffer, uint32_t* ctxt_buffer_len,
        block* auth_tag_buf, uint32_t auth_tag_len
) {

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  };
  const EVP_CIPHER * algorithm = EVP_aes_128_gcm();

  // initialize the cipher object
  // IV and key will be set later.
  assert(EVP_CIPHER_key_length(algorithm) == key_length);
  ERR_CHECK_EVP_CLEANUP(
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
        ERROR_ON_AEAD_ENCRYPTION,
        EVP_CIPHER_CTX_free(ctx));

  // set IV length
  ERR_CHECK_EVP_CLEANUP(
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(*iv), NULL),
        ERROR_ON_AEAD_ENCRYPTION, EVP_CIPHER_CTX_free(ctx));

  // sample an IV
  ERR_CHECK_CLEANUP(next_prg_block(iv), EVP_CIPHER_CTX_free(ctx));

  // set IV and key
  ERR_CHECK_EVP_CLEANUP(
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, (byte*) iv),
        ERROR_ON_AEAD_ENCRYPTION, EVP_CIPHER_CTX_free(ctx));

  // pipe in "associated data" to be authenticated
  int authenticated_data = 0;
  ERR_CHECK_EVP_CLEANUP(
        EVP_EncryptUpdate(ctx, NULL, &authenticated_data, auth_data, auth_data_len),
        ERROR_ON_AEAD_ENCRYPTION, EVP_CIPHER_CTX_free(ctx));
  assert(authenticated_data == auth_data_len);

  // pipe in plaintext
  int bytes_written_on_update = 0;
  ERR_CHECK_EVP_CLEANUP(
        EVP_EncryptUpdate(ctx, ctxt_buffer, &bytes_written_on_update, ptxt, ptxt_len),
        ERROR_ON_AEAD_ENCRYPTION, EVP_CIPHER_CTX_free(ctx));
  assert(bytes_written_on_update <= *ctxt_buffer_len);

  // finish encryption
  int bytes_written_on_final = 0;
  ERR_CHECK_EVP_CLEANUP(
        EVP_EncryptFinal_ex(ctx, ctxt_buffer + bytes_written_on_update, &bytes_written_on_final),
        ERROR_ON_AEAD_ENCRYPTION, EVP_CIPHER_CTX_free(ctx));
  assert(bytes_written_on_update + bytes_written_on_final <= *ctxt_buffer_len);

  // extract the tag
  ERR_CHECK_EVP_CLEANUP(
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, auth_tag_len, auth_tag_buf),
        ERROR_ON_AEAD_ENCRYPTION, EVP_CIPHER_CTX_free(ctx));

  EVP_CIPHER_CTX_free(ctx);

  *ctxt_buffer_len = bytes_written_on_update + bytes_written_on_final;

  return ERROR_NONE;

};


int aes_gcm_decrypt(
        const byte * key, int key_length,
        const byte* auth_data, int auth_data_len,
        const byte* ctxt, int ctxt_len,
        const block* iv, int iv_len,
        byte* ptxt_buffer, uint32_t* ptxt_buffer_len,
        const block* auth_tag_buf, uint32_t auth_tag_len
) {

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  };
  const EVP_CIPHER * algorithm = EVP_aes_128_gcm();

  // initialize the cipher object
  assert(EVP_CIPHER_key_length(algorithm) == key_length);
  ERR_CHECK_EVP_CLEANUP(
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL),
        ERROR_ON_AEAD_DECRYPTION, EVP_CIPHER_CTX_free(ctx));

  // set IV length
  ERR_CHECK_EVP_CLEANUP(
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(*iv), NULL),
        ERROR_ON_AEAD_DECRYPTION, EVP_CIPHER_CTX_free(ctx));

  // set expected auth tag
  ERR_CHECK_EVP_CLEANUP(
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, auth_tag_len, (byte*) auth_tag_buf),
        ERROR_ON_AEAD_DECRYPTION, EVP_CIPHER_CTX_free(ctx));

  // set IV and key
  ERR_CHECK_EVP_CLEANUP(
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, (byte*) iv),
        ERROR_ON_AEAD_DECRYPTION, EVP_CIPHER_CTX_free(ctx));

  // pipe in "associated data" to be authenticated
  int authenticated_data = 0;
  int result = EVP_DecryptUpdate(ctx, NULL, &authenticated_data, auth_data, auth_data_len);
  if (result != 1) {
    memset(ptxt_buffer, 0, *ptxt_buffer_len);
    EVP_CIPHER_CTX_free(ctx);
    return ERROR_ON_AEAD_DECRYPTION;
  };
  assert(authenticated_data == auth_data_len);

  // pipe in ciphertext
  int bytes_written_on_update = 0;
  result = EVP_DecryptUpdate(ctx, ptxt_buffer, &bytes_written_on_update, ctxt, ctxt_len);
  if (result != 1) {
    memset(ptxt_buffer, 0, *ptxt_buffer_len);
    EVP_CIPHER_CTX_free(ctx);
    return ERROR_ON_AEAD_DECRYPTION;
  };
  assert(bytes_written_on_update <= *ptxt_buffer_len);

  // finish decryption
  int bytes_written_on_final = 0;
  result = EVP_DecryptFinal_ex(ctx, ptxt_buffer + bytes_written_on_update, &bytes_written_on_final);
  if (result != 1) {
    memset(ptxt_buffer, 0, *ptxt_buffer_len);
    EVP_CIPHER_CTX_free(ctx);
    return ERROR_ON_AEAD_DECRYPTION;
  };
  assert(bytes_written_on_update + bytes_written_on_final <= *ptxt_buffer_len);

  EVP_CIPHER_CTX_free(ctx);

  *ptxt_buffer_len = bytes_written_on_update + bytes_written_on_final;

  return ERROR_NONE;

};
