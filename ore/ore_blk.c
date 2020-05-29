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

#include "ore_blk.h"
#include "errors.h"
#include "flags.h"

// #include <gmp.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>

// Helper macro for error handling
static int _error_flag;
#define ERR_CHECK(x) if((_error_flag = x) != ERROR_NONE) { return _error_flag; }
#define ERR_CHECK_CLEANUP(x, cleanup_code) if((_error_flag = x) != ERROR_NONE) { cleanup_code; return _error_flag; }

// The ceiling function
#define CEIL(x, y) (((x) + (y) - 1) / (y))


/**
 * A a "key" for the Knuth-shuffle pseudo random permutation (PRP).
 * Instead of actually storing the secret key used to derive the PRP, we store the complete derived PRP.
 */
typedef struct {
  bool initialized;                // Whether the key has been initialized
  uint16_t* shuffled_list;         // The result of applying the Knuth shuffle. This directly represents the PRP.
  uint16_t* inverse_shuffled_list; // Represents the inverse PRP.
  uint32_t block_len;              // The size of the blocks. The PRP will operate on blocks of block_len bits.
} prp_key[1];



// The maximum supported block length in bite (chosen primarily for efficiency
// reasons).
static const int MAX_BLOCK_LEN = 16;


// these functions are implemented further below
static inline int _ore_blk_ciphertext_len_left(ore_blk_params params);
static inline int _ore_blk_ciphertext_len_right(ore_blk_params params);


/**
 * Checks if two ore_blk_params structs are equal
 *
 * @param params1 The first set of parameters
 * @param params2 The second set of parameters
 *
 * @return 1 if they are equal, 0 otherwise
 */
static bool _eq_ore_blk_params(ore_blk_params params1, ore_blk_params params2) {
  return (params1->initialized == params2->initialized) &&
         (params1->nbits == params2->nbits) &&
         (params1->block_len == params2->block_len);
}

/**
 * Checks if an ore_param struct is valid by ensuring that the
 * block length is non-zero and less than the maximum supported block
 * length (MAX_BLOCK_LEN).
 *
 * @param params The parameters to check
 *
 * @return true if the parameters are valid, false otherwise
 */
static bool _is_valid_params(ore_blk_params params) {
  if (!params->initialized) {
    return false;
  } else if (params->block_len == 0 || params->block_len > MAX_BLOCK_LEN) {
    return false;
  }

  return true;
}


int init_ore_blk_params(ore_blk_params params, uint32_t nbits, uint32_t block_len) {
  params->initialized = true;
  params->nbits = nbits;
  params->block_len = block_len;

  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  return ERROR_NONE;
}

int ore_blk_setup(ore_blk_secret_key sk, ore_blk_params params) {
  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  ERR_CHECK(generate_aes_key(&sk->prf_key));
  ERR_CHECK_CLEANUP(generate_aes_key(&sk->prp_key), free_aes_key(&sk->prf_key));
  assert(sizeof(block) == sizeof(sk->aead_key));
  ERR_CHECK_CLEANUP(next_prg_block((block*) &(sk->aead_key)), free_aes_key(&sk->prf_key); free_aes_key(&sk->prp_key));

  memcpy(sk->params, params, sizeof(ore_blk_params));

  sk->initialized = true;

  return ERROR_NONE;

}

int ore_blk_cleanup(ore_blk_secret_key sk) {

  int err1 = free_aes_key(&sk->prf_key);
  int err2 = free_aes_key(&sk->prp_key);

  memset(sk, 0, sizeof(ore_blk_secret_key));

  if (err1 == ERROR_NONE) {
    return err2;
  } else {
    return err1;
  };

}


/**
 * Computes and returns remainder of the integer division dividend / divisor.
 * The byte order of dividend is unspecified.
 *
 * This function is primarily used to compute random values in the range from 0 (including) to divisor (excluding),
 * given a random dividend.
 *
 * @param dividend        A pointer to the number that is to be divided.
 * @param dividend_len    The length of dividend, in bytes. Must be a multiple of sizeof(mp_limb_t).
 * @param divisor         The number that is used to divide dividend.
 *
 * @return the remainder of the division.
 */
static uint32_t longmod(byte* dividend, uint32_t dividend_len, uint32_t divisor) {

  // // We need the division to use a secure algorithm.
  // // mpn_sec_div_qr (hopefully) implements such an algorithm.
  // // However, that function is a little cumbersome to use.

  // assert(dividend_len >= sizeof(mp_limb_t));
  // assert(dividend_len % sizeof(mp_limb_t) == 0);
  // assert(sizeof(mp_limb_t) >= sizeof(divisor));

  // // convert dividend to an mpz_t
  // mpz_t mpz_dividend;
  // mpz_init(mpz_dividend);
  // mpz_import(mpz_dividend, dividend_len, 1, 1, 1, 0, dividend);
  // mp_size_t dividend_size = dividend_len / sizeof(mp_limb_t);
  // mp_limb_t * dividend_data = mpz_limbs_modify(mpz_dividend, dividend_size);

  // // initialize the quotient.
  // // The quotient will not be used, but must be present as an output buffer for mpn_sec_div_qr.
  // mpz_t quotient;
  // mpz_init(quotient);
  // mp_size_t quotient_size = dividend_size;
  // mp_limb_t * quotient_data = mpz_limbs_write(quotient, quotient_size);

  // // initialize the divisor
  // mp_limb_t divisor_data[1] = { divisor };
  // mp_size_t divisor_size = 1;

  // // allocate some more scratch space for mpn_sec_div_qr
  // mp_size_t required_buffer_space = mpn_sec_div_qr_itch(dividend_size, divisor_size);
  // mp_limb_t * buffer = (mp_limb_t*) alloca(required_buffer_space * sizeof(mp_limb_t));

  // // finally, call mpn_sec_div_qr
  // mpn_sec_div_qr(quotient_data, dividend_data, dividend_size, divisor_data, divisor_size, buffer);

  // // mpn_sec_div_qr stores the remainder in dividend_data.
  // mp_limb_t remainder = dividend_data[0];

  // // clean up
  // mpz_clear(mpz_dividend);
  // mpz_clear(quotient);

  // return remainder;

  BN_CTX* ctx;
  ctx = BN_CTX_new();

  BIGNUM *bn_dividend = BN_bin2bn(dividend, dividend_len, NULL);
  uint64_t remainder =  BN_mod_word(bn_dividend, divisor);

  BN_free(bn_dividend);
  BN_CTX_free(ctx);

  return (uint32_t)remainder;
};


/**
 * Initializes the secret key sk for the pseudo random permuation (PRP) from the AES key seed.
 * The PRP inputs and outputs will be blocks of block_len bits.
 * The seed should not be used for other purposes than initializing the PRP.
 *
 * @param sk         The secret key to be initialized.
 * @param seed       The seed for the initialization. This must originate from a strong source of randomness.
 * @param block_len  Defines the domain of the PRP. The PRP will operate on blocks of block_len bits.
 *                   The implementation currently only supports block sizes of up to 16 bits.
 *
 * @return ERROR_NONE on success, and the corresponding error code on failure.
 */
static int small_domain_prp_setup(prp_key sk, const AES_KEY seed, const uint32_t block_len) {

  // check parameters and compute the amount of required memory
  if (block_len > MAX_BLOCK_LEN) {
    return ERROR_PARAMS_INVALID;
  };
  uint32_t domain_size = 1 << block_len;

  // allocate memory for the two lists
  // FIXME: when the block size is less than 16 bits (which will probably be the case),
  // then it might be more space-efficient to store the list in a bit field instead of
  // an array of uint16_t.
  sk->shuffled_list = malloc(domain_size * sizeof(sk->shuffled_list[0]));
  if (sk->shuffled_list == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }
  sk->inverse_shuffled_list = malloc(domain_size * sizeof(sk->shuffled_list[0]));
  if (sk->inverse_shuffled_list == NULL) {
    free(sk->shuffled_list);
    return ERROR_MEMORY_ALLOCATION;
  };

  // initialize memory
  for (uint32_t i = 0; i < domain_size; i++) {
    sk->shuffled_list[i] = i;
    sk->inverse_shuffled_list[i] = i;
  };

  // shuffle
  block out;
  for (uint32_t i = domain_size - 1; i >= 1; i--) {

    pack_block(0, i, &out);

    ERR_CHECK_CLEANUP(aes_eval_in_place(&out, &seed), free(sk->shuffled_list); free(sk->inverse_shuffled_list));

    uint32_t j = longmod((byte*) &out, sizeof(out), i + 1);

    // swap shuffled_list[i] with shuffled_list[j]
    uint16_t val1 = sk->shuffled_list[i];
    uint16_t val2 = sk->shuffled_list[j];
    sk->shuffled_list[i] = val2;
    sk->shuffled_list[j] = val1;

    // do the swap for the inverse_shuffled_list
    sk->inverse_shuffled_list[val1] = j;
    sk->inverse_shuffled_list[val2] = i;

  };

  // set the remaining entries of the the prp key struct
  sk->block_len = block_len;
  sk->initialized = true;

  return ERROR_NONE;

};

/**
 * Cleans up the given PRP key and frees associated memory.
 *
 * @param key    The key to clean up.
 *
 * @return ERROR_NONE on success, otherwise, a corresponding error is returned.
 */
static int small_domain_prp_cleanup(prp_key key) {

  if (!key->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  };

  key->initialized = 0;
  free(key->shuffled_list);
  free(key->inverse_shuffled_list);
  return ERROR_NONE;

};


/**
 * Evaluates the PRP on a single value. The PRP is based on the Knuth shuffle.
 *
 * The input value is taken from the lowest block_len bits of src, where
 * block_len is the parameter that was passed to the call to small_domain_prp_setup when seting up key.
 * The upper bits of src must be zero.
 *
 * The output value is written to dst.
 *
 * @param dst    A buffer (at least block_len bits long) that will hold
 *               the output of the PRP
 * @param key    The key for the PRP. This also defines the block_len.
 * @param src    The input value to the PRP (block_len)
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static int prp_eval(uint16_t * dst, const prp_key key, const uint16_t src) {

  if (!key->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  };

  uint32_t block_len = key->block_len;

  uint16_t input = src;
  if (input >= (1 << block_len)) {
    return ERROR_OUT_OF_RANGE;
  };

  uint16_t output = key->shuffled_list[input];

  *dst = output;

  return ERROR_NONE;

};


/**
 * Evaluates the PRP on a single value.
 *
 * This function is functionally equivalent to creating a prp_key with small_domain_prp_setup(key, seed, block_len),
 * calling prp_eval(dst, key, src), and then freeing the prp key with small_domain_prp_cleanup(key).
 * However, this function is designed to be more efficient when only a single value is queried from the PRP key.
 * (On average, calling this function should be approximately twice as fast as the function call sequence described above.)
 *
 * @param seed       The seed for the initialization of the PRP. Must originate from a strong source of randomness.
 * @param block_len  Defines the domain of the PRP. The PRP will operate on blocks of block_len bits.
 *                   The implementation currently only supports block sizes of up to 16 bits.
 * @param dst        A buffer (at least block_len bits long) that will hold
 *                   the output of the PRP
 * @param src        The input value to the PRP (at most block_len bits, in the least significat bits of src).
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static int prp_eval_once(AES_KEY seed, const uint32_t block_len, uint16_t *dst, const uint16_t src) {

  // check parameters and compute the amount of required memory
  if (block_len > MAX_BLOCK_LEN) {
    return ERROR_PARAMS_INVALID;
  };
  uint32_t domain_size = 1 << block_len;
  uint16_t input = src;
  if (input >= domain_size) {
    return ERROR_OUT_OF_RANGE;
  };

  //allocate memory
  uint16_t* shuffled_list = malloc(domain_size * sizeof(uint16_t));
  if (shuffled_list == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  // initialize memory
  for (uint32_t i = 0; i < domain_size; i++) {
    shuffled_list[i] = i;
  };

  // shuffle
  block out;
  for (uint32_t i = domain_size - 1; i >= 1 && i >= input; i--) {

    pack_block(0, i, &out);

    ERR_CHECK_CLEANUP(aes_eval_in_place(&out, &seed), free(shuffled_list));

    uint32_t j = longmod((byte*) &out, sizeof(out), i + 1);

    // swap shuffled_list[i] with shuffled_list[j]
    uint16_t helper = shuffled_list[i];
    shuffled_list[i] = shuffled_list[j];
    shuffled_list[j] = helper;

  };

  *dst = shuffled_list[input];

  free(shuffled_list);

  return ERROR_NONE;

};


/**
 * Evaluates the inverse PRP on a single value.
 *
 * The input value is taken from the lowest block_len bits of src, where
 * block_len is the parameter that was passed to the call to small_domain_prp_setup when setting up key.
 * The upper bits of src must be zero.
 *
 * The output value is written to dst.
 *
 * @param dst    A buffer (at least block_len bits long) that will hold
 *               the output of the inverse PRP
 * @param key    The key for the PRP. This also defines the block_len.
 * @param src    The input value to the inverse PRP (block_len)
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
*/
static int prp_inv_eval(uint16_t* dst, const prp_key key, const uint16_t src) {

  if (!key->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  };

  uint32_t block_len = key->block_len;

  uint16_t input = src;
  if (input >= (1 << block_len)) {
    return ERROR_OUT_OF_RANGE;
  };

  uint16_t output = key->inverse_shuffled_list[input];

  *dst = output;

  return ERROR_NONE;

};

/**
 * Evaluates a the inverse PRP (on a block_len bits domain) on all of the values
 * in the domain. The PRP is based on the Knuth shuffle.
 * block_len is the parameter passed to small_domain_prp_setup when initializing key.
 *
 * This function sets *dst to point to an array of all 2**block_len outputs of the inverse PRP
 * The array will hold all of the outputs of the PRP inverse (values from 0, 1, ... , 2^nbits - 1).
 * This array will be available in memory until the key is cleared with small_domain_prp_cleanup.
 * The array must not be modified.
 * The array may no longer be accessed after the call to small_domain_prp_cleanup.
 * If the caller needs to the returned values after the call to small_domain_prp_cleanup,
 * the caller should create a copy with memcpy().
 *
 * @param dst    The output of this function: *dst will be set to point to the array holding the inverse PRP.
 * @param key    The key for the PRP
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
*/
static int prp_inv_eval_all(const uint16_t** dst, const prp_key key) {

  if (!key->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  };

  *dst = key->inverse_shuffled_list;

  return ERROR_NONE;

};


#ifdef USE_AES_RO
  /**
   * Evaluates a keyed hash function on a particular value (used to construct
   * the right ciphertexts). This function uses AES to instantiate the random
   * oracle: H(k, x) = AES(x, k). This is sound, for instance, if we model
   * AES as an ideal cipher.
   *
   * @param out  A pointer to an integer that will be set to the result of the hash function (mod 3)
   * @param key  The key to the keyed hash function
   * @param val  The value to evaluate the hash function on
   *
   * @return ERROR_NONE on success and a corresponding error code on failure
   *         (see errors.h for the full list of possible error codes)
   */
  static inline int _eval_keyed_hash_aes_ro(uint8_t* out, const block key, const block val) {
    AES_KEY aes_key;
    setup_aes_key(&aes_key, (byte*) &val, sizeof(block));

    block output;
    ERR_CHECK_CLEANUP(aes_eval(&output, &aes_key, key), free_aes_key(&aes_key));

    ERR_CHECK(free_aes_key(&aes_key));

    *out = (uint8_t) longmod((byte*) &output, sizeof(output), 3);

    return ERROR_NONE;
  }

  /**
   * Evaluates a keyed hash function on a single value using multiple keys
   * (used to construct the right ciphertexts). This function uses AES to
   * instantiate the particular random oracle: H(k, x) = lsb(AES(x, k)). Batch
   * evaluation of AES can be pipelined (assuming support for the AES-NI
   * instruction set), becuase the same value is used (x is reused across all
   * of the invocations).
   *
   * @param out      An output buffer to store the vector of outputs of the
   *                 hash function (assumed to be of the correct size).
   *                 Each output is stored in a separate byte.
   * @param nblocks  The number of hash function evaluations
   * @param keys     The vector of keys (of length nblocks) used to apply the
   *                 hash function
   * @param val      The value to evaluate the hash functions on
   *
   * @return ERROR_NONE on success and a corresponding error code on failure
   *         (see errors.h for the full list of possible error codes)
   */
  static inline int _eval_keyed_hash_batch_aes_ro(uint8_t* out, uint32_t nblocks,
                                                  const block* keys, const block val) {
    AES_KEY aes_key;
    setup_aes_key(&aes_key, (byte*) &val, sizeof(block));

    block* outputs = malloc(nblocks * sizeof(block));
    ERR_CHECK_CLEANUP(aes_eval_blocks(outputs, nblocks, &aes_key, keys), free(outputs); free_aes_key(&aes_key));
    ERR_CHECK_CLEANUP(free_aes_key(&aes_key), free(outputs));

    for (int i = 0; i < nblocks; i++) {
      out[i] = (uint8_t) longmod((byte*) &(outputs[i]), sizeof(outputs[i]), 3);
    }

    free(outputs);

    return ERROR_NONE;
  }
#elif defined(USE_HMAC_SHA256_RO)
  /**
   * Evaluates a keyed hash function on a particular value (used to construct
   * the right ciphertexts). This function uses HMAC-SHA256 to instantiate the
   * random oracle: H(k, x) = HMAC(k, x) % 3.
   *
   * @param out  A pointer to an integer that will be set to the result of the hash function (mod 3)
   * @param key  The key to the keyed hash function
   * @param val  The value to evaluate the hash function on
   *
   * @return ERROR_NONE on success and a corresponding error code on failure
   *         (see errors.h for the full list of possible error codes)
   */
  static inline int _eval_keyed_hash_hmac_sha256(uint8_t* out, const block key, const block val) {
    static byte output_buf[SHA256_OUTPUT_BYTES];
    static unsigned int output_len;
    byte * result = HMAC(EVP_sha256(), (byte*) &key, sizeof(key), (byte*) &val, sizeof(val), output_buf, &output_len);
    if (result != output_buf) {
      return ERROR_ON_HASH;
    };
    assert(output_len == SHA256_OUTPUT_BYTES);

    *out = longmod(output_buf, output_len, 3);

    return ERROR_NONE;

  };
#else
  /**
   * Evaluates a keyed hash function on a particular value (used to construct
   * the right ciphertexts). This function uses SHA-256 to instantiate the
   * random oracle: H(k, x) = (SHA-256(k || x)) % 3.
   *
   * @param out  A pointer to an integer that will be set to the result of the hash function (mod 3)
   * @param key  The key to the keyed hash function
   * @param val  The value to evaluate the hash function on
   *
   * @return ERROR_NONE on success and a corresponding error code on failure
   *         (see errors.h for the full list of possible error codes)
   */
  static inline int _eval_keyed_hash_sha256(uint8_t* out, const block key, const block val) {
    static byte inputbuf[AES_OUTPUT_BYTES + sizeof(block)];
    memcpy(inputbuf, &key, sizeof(block));
    memcpy(inputbuf + sizeof(block), &val, sizeof(block));

    byte dst[SHA256_OUTPUT_BYTES];
    ERR_CHECK(sha_256(dst, sizeof(dst), inputbuf, sizeof(inputbuf)));
    
    *out = longmod(dst, sizeof(dst), 3);

    return ERROR_NONE;
  }
#endif

/**
 * Evaluates a keyed hash function on a particular value (used to construct
 * the right ciphertexts). The precise details are described in Section 3.1 of
 * the paper (https://eprint.iacr.org/2016/612.pdf). In the security analysis,
 * the hash function is modeled as a random oracle. We give three instantiations
 * based on different choices of the random oracle. The first is based on AES
 * (provably secure if we model AES as an ideal cipher), the second is
 * based on the more traditional SHA-256, the third is based on HMAC-SHA256.
 * The choice of hash function can be controlled by setting/unsetting
 * the USE_AES_RO/USE_HMAC_SHA256_RO flag in flags.h.
 *
 * @param out  An output buffer to store the output of the hash function
 *             (assumed to be of the correct size)
 * @param key  The key to the keyed hash function
 * @param val  The value to evaluate the hash function on
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static inline int _eval_keyed_hash(uint8_t* out, const block key, const block val) {
  #ifdef USE_AES_RO
    return _eval_keyed_hash_aes_ro(out, key, val);
  #elif defined(USE_HMAC_SHA256_RO)
    return _eval_keyed_hash_hmac_sha256(out, key, val);
  #else
    return _eval_keyed_hash_sha256(out, key, val);
  #endif
}

/**
 * Evaluates a keyed hash function using multiple keys on the same block.
 * Using the AES-based random oracle instantiation together with AES-NI,
 * the batch version is faster (by pipelining the evaluations of the AES
 * round functions). With SHA-256, we just invoke the keyed hash separately
 * using each of the keys.
 *
 * @param out      An output buffer to store the vector of outputs of the hash
 *                 function (assumed to be of the correct size)
 * @param nblocks  The number of hash function evaluations
 * @param keys     The vector of keys (of length nblocks) used to apply the hash function
 * @param val      The value to evaluate the hash functions on
 *
 * @return ERROR_NONE on success and a corresponding error code on failure
 *         (see errors.h for the full list of possible error codes)
 */
static inline int _eval_keyed_hash_batch(uint8_t* out, uint32_t nblocks,
                                         const block* keys, const block val) {
  #ifdef USE_AES_RO
    return _eval_keyed_hash_batch_aes_ro(out, nblocks, keys, val);
  #else
    for (int i = 0; i < nblocks; i++) {
      #ifdef USE_HMAC_SHA256_RO
        ERR_CHECK(_eval_keyed_hash_hmac_sha256(&out[i], keys[i], val));
      #else
        ERR_CHECK(_eval_keyed_hash_sha256(&out[i], keys[i], val));
      #endif
    }
    return ERROR_NONE;
  #endif
}

/**
  * Encrypts a single block of the ORE plaintext (using the small-domain ORE)
  * to its respective representation in the left ciphertext.
  * 
  * This algorithm is described in Section 3 of the paper
  * (https://eprint.iacr.org/2016/612.pdf).
  *
  * @param comp_left   A buffer to hold the left ciphertext component
  * @param sk          The secret key for the ORE scheme
  * @param block_ind   The index of the current block (used to construct a PRF
  *                    on variable-length inputs)
  * @param prefix      The prefix of the current block (used for key
  *                    derivation for encrypting the current block)
  * @param val         The value of the block to be encrypted (at the current
  *                    index)
  *
  * @return ERROR_NONE on success and a corresponding error code on failure
  *         (see errors.h for the full list of possible error codes)
  */
static int _ore_blk_encrypt_block_left(byte* comp_left, ore_blk_secret_key sk,
                                  uint64_t block_ind, uint64_t prefix, uint64_t val) {

  uint32_t block_len = sk->params->block_len;

  // derive PRP key for this prefix
  // Step 3a of the specification
  block prp_key_buf;
  pack_block(block_ind, prefix, &prp_key_buf);
  ERR_CHECK(aes_eval_in_place(&prp_key_buf, &sk->prp_key));

  AES_KEY prp_seed;
  ERR_CHECK(setup_aes_key(&prp_seed, (byte*) &prp_key_buf, sizeof(prp_key_buf)));

  // construct left ciphertext (PRP evaluation on the value)
  // Step 3b of the specification
  uint64_t pix = 0;
  ERR_CHECK_CLEANUP(prp_eval_once(prp_seed, sk->params->block_len, (uint16_t*) &pix, (uint16_t) val), free_aes_key(&prp_seed));
  ERR_CHECK(free_aes_key(&prp_seed));

  // Step 3c of the specification
  block key;
  uint64_t prefix_shifted = prefix << block_len;
  pack_block(block_ind, prefix_shifted | pix, &key);
  ERR_CHECK(aes_eval_in_place(&key, &sk->prf_key));
  memcpy(comp_left, &key, sizeof(block));
  memcpy(comp_left + sizeof(block), &pix, CEIL(block_len, 8));

  return ERROR_NONE;
}



int ore_blk_encrypt_ui_left(ore_blk_ciphertext_left ctxt, ore_blk_secret_key sk, uint64_t msg) {
  if (!sk->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  }

  if (!ctxt->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  if (!_eq_ore_blk_params(ctxt->params, sk->params)) {
    return ERROR_PARAMS_MISMATCH;
  }

  if (!_is_valid_params(ctxt->params)) {
    return ERROR_PARAMS_INVALID;
  }

  uint32_t nbits = ctxt->params->nbits;
  uint32_t block_len = ctxt->params->block_len;
  uint32_t nblocks = CEIL(nbits, block_len);

  uint64_t block_mask = (1 << block_len) - 1;
  block_mask <<= (block_len * (nblocks - 1));

  // set up left and right pointers for each block
  byte* comp_left = ctxt->comp_left;

  uint32_t len_left_block  = AES_BLOCK_LEN + CEIL(block_len, 8);

  // process each block
  // Step 3 of the specification
  uint64_t prefix = 0;
  for(int i = 0; i < nblocks; i++) {
    uint64_t cur_block = msg & block_mask;
    cur_block >>= block_len * (nblocks - i - 1);

    block_mask >>= block_len;

    ERR_CHECK(_ore_blk_encrypt_block_left(comp_left, sk, i, prefix, cur_block));

    // update prefix
    prefix <<= block_len;
    prefix |= cur_block;

    // update block pointers
    comp_left  += len_left_block;
  }

  // aead encryption
  // Step 4 of the specification
  uint32_t aead_ciphertext_length = sizeof(ctxt->aead_ciphertext);
  ERR_CHECK(aes_gcm_encrypt(
        sk->aead_key, sizeof(sk->aead_key),
        ctxt->comp_left, _ore_blk_ciphertext_len_left(sk->params),
        (byte*) &msg, sizeof(msg),
        &(ctxt->iv), sizeof(ctxt->iv),
        ctxt->aead_ciphertext, &aead_ciphertext_length,
        &(ctxt->auth_tag), sizeof(ctxt->auth_tag)
  ));
  assert(aead_ciphertext_length == sizeof(ctxt->aead_ciphertext));

  return ERROR_NONE;
}

/**
  * Encrypts a single block of the ORE ciphertext (using the small-domain ORE)
  * to a right ciphertext.
  * This algorithm is described in Section 3 of the paper
  * (https://eprint.iacr.org/2016/612.pdf).
  *
  * @param comp_right  A buffer to hold the right ciphertext component
  * @param sk          The secret key for the ORE scheme
  * @param nonce       The nonce used for encryption (should be unique for
  *                    each ciphertext)
  * @param block_ind   The index of the current block (used to construct a PRF
  *                    on variable-length inputs)
  * @param prefix      The prefix of the current block (used for key
  *                    derivation for encrypting the current block)
  * @param val         The value of the block to be encrypted (at the current
  *                    index)
  *
  * @return ERROR_NONE on success and a corresponding error code on failure
  *         (see errors.h for the full list of possible error codes)
  */
static int _ore_blk_encrypt_block_right(byte* comp_right, ore_blk_secret_key sk,
                                  block nonce, uint64_t block_ind, uint64_t prefix, uint64_t val) {
  uint32_t block_len = sk->params->block_len;
  uint32_t nslots = 1 << block_len;

  // derive PRP key for this prefix
  // This can be precomputed for Step 3a i., since the key for the PRP does not depend on j.
  block prp_key_buf;
  pack_block(block_ind, prefix, &prp_key_buf);
  ERR_CHECK(aes_eval_in_place(&prp_key_buf, &sk->prp_key));

  AES_KEY prp_seed;
  ERR_CHECK(setup_aes_key(&prp_seed, (byte*) &prp_key_buf, sizeof(block)));
  prp_key prp_sk;
  ERR_CHECK_CLEANUP(small_domain_prp_setup(prp_sk, prp_seed, sk->params->block_len), free_aes_key(&prp_seed));

  ERR_CHECK_CLEANUP(free_aes_key(&prp_seed), small_domain_prp_cleanup(prp_sk));

  // construct right ciphertext (encryption of comparison vector under keys
  // derived from PRF)
  // Step 3a (i, ii, and iii) are each done en-block.
  uint64_t prefix_shifted = prefix << block_len;
  block* inputs = malloc(sizeof(block) * nslots);
  block* keys   = malloc(sizeof(block) * nslots);
  for (int i = 0; i < nslots; i++) {
    pack_block(block_ind, prefix_shifted | i, &(inputs[i]));
  }
  // Step 3a ii
  ERR_CHECK_CLEANUP(
      aes_eval_blocks(keys, nslots, &sk->prf_key, inputs),
      small_domain_prp_cleanup(prp_sk); free(inputs); free(keys)
  );
  free(inputs);

  const uint16_t* pi_inv;
  ERR_CHECK_CLEANUP(prp_inv_eval_all(&pi_inv, prp_sk), small_domain_prp_cleanup(prp_sk); free(keys));

  // Step 3a iii
  uint8_t* r = malloc(sizeof(uint8_t) * nslots);
  ERR_CHECK_CLEANUP(_eval_keyed_hash_batch(r, nslots, keys, nonce), small_domain_prp_cleanup(prp_sk); free(keys); free(r));
  free(keys);

  // Step 3a iv
  for (int i = 0; i < nslots; i++) {

    uint8_t v;
    // pi_inv[i] is called j in the specification, so this is essentially Step 3a i
    if (pi_inv[i] == val) {
      v = 0;
    } else if (pi_inv[i] < val) {
      v = 2;
    } else {
      v = 1;
    };
    r[i] = (r[i] + v) % 3;

  }

  // export to the ciphertext
  // we pack up to four values between 0 and 3 into a single byte.
  for (int i = 0; i < nslots / 4; i++) {
    uint8_t next_byte = 0;
    for (int j = 0; i*4 + j < nslots && j < 4; j++) {
      next_byte <<= 2;
      assert(r[i * 4 + j] < 3);
      next_byte |= r[i * 4 + j];
    };
    *comp_right = next_byte;
    comp_right++;
  };

  if (block_len < 2) {
    // If block_len == 1, then nslots == 2, so the body of the for loop above was never executed.
    // This is a workaround for that case.
    *comp_right = r[0] << 6 | r[1] << 4;
  };

  free(r);
  ERR_CHECK(small_domain_prp_cleanup(prp_sk));

  return ERROR_NONE;

}

int ore_blk_encrypt_ui_right(ore_blk_ciphertext_right ctxt, ore_blk_secret_key sk, uint64_t msg) {
  if (!sk->initialized) {
    return ERROR_SK_NOT_INITIALIZED;
  }

  if (!ctxt->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  if (!_eq_ore_blk_params(ctxt->params, sk->params)) {
    return ERROR_PARAMS_MISMATCH;
  }

  if (!_is_valid_params(ctxt->params)) {
    return ERROR_PARAMS_INVALID;
  }

  uint32_t nbits = ctxt->params->nbits;
  uint32_t block_len = ctxt->params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(nbits, block_len);

  uint64_t block_mask = (1 << block_len) - 1;
  block_mask <<= (block_len * (nblocks - 1));

  // choose nonce
  // Step 2 of the specification
  block nonce;
  ERR_CHECK(next_prg_block(&nonce));
  memcpy(ctxt->comp_right, &nonce, sizeof(block));

  // set up pointer to right data
  byte* comp_right = ctxt->comp_right + sizeof(block);
  uint32_t len_right_block = CEIL(nslots, 4);

  // process each block
  // Step 3 of the specification
  uint64_t prefix = 0;
  for(int i = 0; i < nblocks; i++) {
    uint64_t cur_block = msg & block_mask;
    cur_block >>= block_len * (nblocks - i - 1);

    block_mask >>= block_len;

    ERR_CHECK(_ore_blk_encrypt_block_right(comp_right, sk, nonce, i, prefix, cur_block));

    // update prefix
    prefix <<= block_len;
    prefix |= cur_block;

    // update block pointers
    comp_right += len_right_block;
  }

  // aead encryption
  // Step 4 of the specification
  uint32_t aead_ciphertext_length = sizeof(ctxt->aead_ciphertext);
  ERR_CHECK(aes_gcm_encrypt(
        sk->aead_key, sizeof(sk->aead_key),
        ctxt->comp_right, _ore_blk_ciphertext_len_right(sk->params),
        (byte*) &msg, sizeof(msg),
        &(ctxt->iv), sizeof(ctxt->iv),
        ctxt->aead_ciphertext, &aead_ciphertext_length,
        &(ctxt->auth_tag), sizeof(ctxt->auth_tag)
  ));
  assert(aead_ciphertext_length == sizeof(ctxt->aead_ciphertext));

  return ERROR_NONE;
}

int ore_blk_compare(int* result_p, ore_blk_ciphertext_left ctxt1, ore_blk_ciphertext_right ctxt2) {
  if (!ctxt1->initialized || !ctxt2->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  if (!_eq_ore_blk_params(ctxt1->params, ctxt2->params)) {
    return ERROR_PARAMS_MISMATCH;
  }

  if (!_is_valid_params(ctxt1->params)) {
    return ERROR_PARAMS_INVALID;
  }

  uint32_t nbits = ctxt1->params->nbits;
  uint32_t block_len = ctxt1->params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(nbits, block_len);

  block nonce = *(block*) ctxt2->comp_right;

  uint32_t offset_left = 0;
  uint32_t offset_right = sizeof(block);

  uint32_t len_left_block  = AES_BLOCK_LEN + CEIL(block_len, 8);
  uint32_t len_right_block = CEIL(nslots, 4);

  // compare each block
  // Step 2 and 3 and 4 of the specification are mixed together here.
  // We simply look for an i where there is a difference.
  for (int i = 0; i < nblocks; i++) {

    // extract data from the left encryption of block i
    block key;
    memcpy(&key, ctxt1->comp_left + offset_left, sizeof(block));
    uint32_t index = 0;
    memcpy(&index, ctxt1->comp_left + offset_left + sizeof(block), CEIL(block_len, 8));

    uint8_t hash;
    ERR_CHECK(_eval_keyed_hash(&hash, key, nonce));
    assert(hash < 3);

    // extract data from the right encryption of block i
    uint8_t z = *(ctxt2->comp_right + offset_right + index / 4);
    z >>= 6 - (2 * (index % 4));
    z &= 0x3;
    assert(z < 3);

    // compare this block
    // Step 4 of the specification.
    if (hash != z) {
      int result = (z - hash + 3) % 3; // + 3, so we don't have to care about negative numbers when computing the modulo
      if (result == 2) {
        *result_p = -1;
      } else {
        *result_p = result;
      };
      return ERROR_NONE;
    };

    // increment offsets for the next iteration
    offset_left  += len_left_block;
    offset_right += len_right_block;

  }

  // all the z are equal to the hash values, so the ciphertexts encrypt identical plaintexts.
  // The "then" part of Step 2 of the specification.
  *result_p = 0;

  return ERROR_NONE;

}

int ore_blk_decrypt_ui_left(ore_blk_ciphertext_left ctxt, ore_blk_secret_key sk, uint64_t* msg) {

  uint32_t bytes_decrypted = sizeof(*msg);
  int result = aes_gcm_decrypt(
    sk->aead_key, sizeof(sk->aead_key),
    ctxt->comp_left, _ore_blk_ciphertext_len_left(sk->params),
    ctxt->aead_ciphertext, sizeof(ctxt->aead_ciphertext),
    &(ctxt->iv), sizeof(ctxt->iv),
    (byte*) msg, &bytes_decrypted,
    &(ctxt->auth_tag), sizeof(ctxt->auth_tag)
  );
  if (result == ERROR_NONE && bytes_decrypted != sizeof(*msg)) {
    return ERROR_ON_AEAD_DECRYPTION;
  } else {
    return result;
  };

};


int ore_blk_decrypt_ui_right(ore_blk_ciphertext_right ctxt, ore_blk_secret_key sk, uint64_t* msg) {

  uint32_t bytes_decrypted = sizeof(*msg);
  int result = aes_gcm_decrypt(
    sk->aead_key, sizeof(sk->aead_key),
    ctxt->comp_right, _ore_blk_ciphertext_len_right(sk->params),
    ctxt->aead_ciphertext, sizeof(ctxt->aead_ciphertext),
    &(ctxt->iv), sizeof(ctxt->iv),
    (byte*) msg, &bytes_decrypted,
    &(ctxt->auth_tag), sizeof(ctxt->auth_tag)
  );
  if (result == ERROR_NONE && bytes_decrypted != sizeof(*msg)) {
    return ERROR_ON_AEAD_DECRYPTION;
  } else {
    return result;
  };

};

/**
 * Computes the length of a left ciphertext.
 *
 * @param params The parameters for the ORE scheme
 *
 * @return the length of a left ciphertext for the specific choice of
 *         parameters
 */
static inline int _ore_blk_ciphertext_len_left(ore_blk_params params) {
  uint32_t nblocks = CEIL(params->nbits, params->block_len);

  return (AES_BLOCK_LEN + CEIL(params->block_len, 8)) * nblocks;
}

/**
 * Computes the length of a right ciphertext.
 *
 * @param params The parameters for the ORE scheme
 *
 * @return the length of a right ciphertext for the specific choice of
 *         parameters
 */
static inline int _ore_blk_ciphertext_len_right(ore_blk_params params) {
  uint32_t block_len = params->block_len;
  uint32_t nslots = 1 << block_len;
  uint32_t nblocks = CEIL(params->nbits, block_len);

  return AES_BLOCK_LEN + CEIL(nslots, 4) * nblocks;
}

int init_ore_blk_ciphertext_left(ore_blk_ciphertext_left ctxt, ore_blk_params params) {
  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  if (ctxt == NULL || params == NULL) {
    return ERROR_NULL_POINTER;
  }

  ctxt->comp_left = malloc(_ore_blk_ciphertext_len_left(params));
  if (ctxt->comp_left == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  memcpy(ctxt->params, params, sizeof(ore_blk_params));

  ctxt->initialized = true;

  return ERROR_NONE;
}

int init_ore_blk_ciphertext_right(ore_blk_ciphertext_right ctxt, ore_blk_params params) {
  if (!_is_valid_params(params)) {
    return ERROR_PARAMS_INVALID;
  }

  if (ctxt == NULL || params == NULL) {
    return ERROR_NULL_POINTER;
  }

  ctxt->comp_right = malloc(_ore_blk_ciphertext_len_right(params));
  if (ctxt->comp_right == NULL) {
    return ERROR_MEMORY_ALLOCATION;
  }

  memcpy(ctxt->params, params, sizeof(ore_blk_params));

  ctxt->initialized = true;

  return ERROR_NONE;
}

int clear_ore_blk_ciphertext_left(ore_blk_ciphertext_left ctxt) {
  if (ctxt == NULL) {
    return ERROR_NONE;
  }

  if (!_is_valid_params(ctxt->params)) {
    return ERROR_PARAMS_INVALID;
  }

  memset(ctxt->comp_left, 0, _ore_blk_ciphertext_len_left(ctxt->params));
  free(ctxt->comp_left);

  memset(ctxt, 0, sizeof(ore_blk_ciphertext_left));

  return ERROR_NONE;
}

int clear_ore_blk_ciphertext_right(ore_blk_ciphertext_right ctxt) {
  if (ctxt == NULL) {
    return ERROR_NONE;
  }

  if (!_is_valid_params(ctxt->params)) {
    return ERROR_PARAMS_INVALID;
  }

  memset(ctxt->comp_right, 0, _ore_blk_ciphertext_len_right(ctxt->params));
  free(ctxt->comp_right);

  memset(ctxt, 0, sizeof(ore_blk_ciphertext_right));

  return ERROR_NONE;
}

/**
 * Returns the size of the AEAD ciphertext (including IV and auth tag).
 */
static inline int ore_blk_aead_ciphertext_size() {
  // a dummy instance so we have something to use sizeof() on.
  ore_blk_ciphertext_left ctxt;
  return sizeof(ctxt->iv)
	  + sizeof(ctxt->aead_ciphertext)
	  + sizeof(ctxt->auth_tag);
};

int ore_blk_comp_left_ciphertext_size(ore_blk_params params) {
  return _ore_blk_ciphertext_len_left(params);
}

int ore_blk_comp_right_ciphertext_size(ore_blk_params params) {
  return _ore_blk_ciphertext_len_right(params);
}

int ore_blk_total_left_ciphertext_size(ore_blk_params params) {
  return ore_blk_comp_left_ciphertext_size(params) + ore_blk_aead_ciphertext_size();
};

int ore_blk_total_right_ciphertext_size(ore_blk_params params) {
  return ore_blk_comp_right_ciphertext_size(params) + ore_blk_aead_ciphertext_size();
};

