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
#include "ore_blk.h"
#include "errors.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int _error;
#define ERR_CHECK(x) if((_error = x) != ERROR_NONE) { return _error; }

static const int N_TRIALS = 500;

/**
 * Returns the signum of the given integer.
 * The signum is 0 if the input is 0,
 * -1 if the input is < 0 and +1 if the input is > 0.
 *
 * @param i    The integer which signum is to be computed
 * @return     the signum of i.
 */
int sgn(int i) {
  if (i == 0) {
    return 0;
  } else if (i < 0) {
    return -1;
  } else {
    return 1;
  };
};

/**
 * test encryption, decryption, and comparison behaviour of the block-wise
 * ORE scheme for the given parameters and numbers.
 * Additionally, test decryption fails if the ciphertext is manipulated by random bitflip.
 *
 * @return 0 on success, -1 on failure, and an error if it occurred during the
 * encryption or comparison phase
 */
static int test(ore_blk_params params, uint64_t n1, uint64_t n2) {

  int cmp = (n1 < n2) ? -1 : 1;
  if (n1 == n2) {
    cmp = 0;
  }

  ore_blk_secret_key sk;
  ERR_CHECK(ore_blk_setup(sk, params));

  ore_blk_ciphertext_left ctxt1;
  ERR_CHECK(init_ore_blk_ciphertext_left(ctxt1, params));

  ore_blk_ciphertext_right ctxt2;
  ERR_CHECK(init_ore_blk_ciphertext_right(ctxt2, params));

  ERR_CHECK(ore_blk_encrypt_ui_left(ctxt1, sk, n1));
  ERR_CHECK(ore_blk_encrypt_ui_right(ctxt2, sk, n2));

  int ret = 0;
  int res;
  ERR_CHECK(ore_blk_compare(&res, ctxt1, ctxt2));
  res = sgn(res);
  if (res != cmp) {
    fprintf(stderr, "signum comparison failed\n");
    ret = -1;
  }

  // test decryption
  uint64_t decryption_left;
  uint64_t decryption_right;
  ERR_CHECK(ore_blk_decrypt_ui_left(ctxt1, sk, &decryption_left));
  ERR_CHECK(ore_blk_decrypt_ui_right(ctxt2, sk, &decryption_right));
  if (decryption_left != n1 || decryption_right != n2) {
    fprintf(stderr, "decryption failed\n");
    ret = -1;
  };

  // test the authentication
  // We modify the ciphertexts by a random bitflip. As a result, the decryption should fail.
  int bitflip = 1 << (rand() % 8);
  int choice = rand() % 4;
  if (choice == 0) {
    // change the comparison data
    ctxt1->comp_left[rand() % ore_blk_comp_left_ciphertext_size(sk->params)] ^= bitflip;
    ctxt2->comp_right[rand() % ore_blk_comp_right_ciphertext_size(sk->params)] ^= bitflip;
  } else if (choice == 1) {
    // change the IV
    byte* iv = (byte*) &ctxt1->iv;
    iv[rand() % sizeof(ctxt1->iv)] ^= bitflip;
    iv = (byte*) &ctxt2->iv;
    iv[rand() % sizeof(ctxt2->iv)] ^= bitflip;
  } else if (choice == 2) {
    // change the AEAD ciphertext
    ctxt1->aead_ciphertext[rand() % sizeof(ctxt1->aead_ciphertext)] ^= bitflip;
    ctxt2->aead_ciphertext[rand() % sizeof(ctxt1->aead_ciphertext)] ^= bitflip;
  } else if (choice == 3) {
    // change the auth tag
    byte* auth_tag = (byte*) &ctxt1->auth_tag;
    auth_tag[rand() % sizeof(ctxt1->auth_tag)] ^= bitflip;
    auth_tag = (byte*) &ctxt2->auth_tag;
    auth_tag[rand() % sizeof(ctxt2->auth_tag)] ^= bitflip;
  };
  int result = ore_blk_decrypt_ui_left(ctxt1, sk, &decryption_left);
  if (result == ERROR_NONE) {
    fprintf(stderr, "decryption of tampered left ciphertext succeeded, but should have failed\n");
    return -1;
  };
  result = ore_blk_decrypt_ui_right(ctxt2, sk, &decryption_right);
  if (result == ERROR_NONE) {
    fprintf(stderr, "decryption of tampered right ciphertext succeeded, but should have failed\n");
    return -1;
  };

  ERR_CHECK(clear_ore_blk_ciphertext_left(ctxt1));
  ERR_CHECK(clear_ore_blk_ciphertext_right(ctxt2));

  return ret;

};

/**
 * Generates two random 32-bit integers and encrypts them (with an 8-bit block size).
 *
 * The encrypted integers are chosen randomly.
 *
 * @return 0 on success, -1 on failure, and an error if it occurred during the
 * encryption or comparison phase
 */
static int test_ore_blk_random() {

  int nbits = 32;
  int block_len = 8;

  uint64_t n1 = rand() % (((uint64_t) 1) << nbits);
  uint64_t n2 = rand() % (((uint64_t) 1) << nbits);

  ore_blk_params params;
  ERR_CHECK(init_ore_blk_params(params, nbits, block_len));

  return test(params, n1, n2);

}


int main(int argc, char** argv) {
  srand((unsigned) time(NULL));

  printf("Testing ORE... \n");
  fflush(stdout);

  ore_blk_params params_64;
  ERR_CHECK(init_ore_blk_params(params_64, 64, 2));

#define DO_TEST(p, n1, n2) \
  { int _result = test(p, n1, n2); \
    if (_result == -1) {           \
      fprintf(stderr, "test with input params %lu, %lu failed\n", (uint64_t) n1, (uint64_t) n2); \
    };                             \
  }

  DO_TEST(params_64, 0, 0); // equality of zero
  DO_TEST(params_64, 0, 1); // comparing 0 and 1
  DO_TEST(params_64, 1, 0);
  DO_TEST(params_64, 1, 1); // comparing 1 and 1
  DO_TEST(params_64, 0, 3); // comparing 0 with the maximum of a one-block number
  DO_TEST(params_64, 3, 0);
  DO_TEST(params_64, 3, 3); // comparing maximum of a one-block number
  DO_TEST(params_64, 4, 3); // comparing a one-block number with a two-block number
  DO_TEST(params_64, 3, 4);
  DO_TEST(params_64, 4, 4);

  // greater numbers
  DO_TEST(params_64, (1<<16),     (1<<16));
  DO_TEST(params_64, (1<<16) - 1, (1<<16));
  DO_TEST(params_64, (1<<16) + 1, (1<<16));
  DO_TEST(params_64, (1<<16),     (1<<16) - 1);
  DO_TEST(params_64, (1<<16),     (1<<16) + 1);
  DO_TEST(params_64, (1<<16) + 1, (1<<16) + 1);

  // even greater numbers
  DO_TEST(params_64, (1lu<<32),     (1lu<<32));
  DO_TEST(params_64, (1lu<<32) - 1, (1lu<<32));
  DO_TEST(params_64, (1lu<<32) + 1, (1lu<<32));
  DO_TEST(params_64, (1lu<<32),     (1lu<<32) + 1);
  DO_TEST(params_64, (1lu<<32),     (1lu<<32) - 1);
  DO_TEST(params_64, (1lu<<32) + 1, (1lu<<32) + 1);

  // test data that has failed
  DO_TEST(params_64, 20100446945lu, 27831388078lu);

  // test with numbers close to UINT64_MAX
  DO_TEST(params_64, UINT64_MAX - 4, UINT64_MAX - 4);
  DO_TEST(params_64, UINT64_MAX - 3, UINT64_MAX - 4);
  DO_TEST(params_64, UINT64_MAX - 4, UINT64_MAX - 3);
  DO_TEST(params_64, UINT64_MAX - 3, UINT64_MAX - 3);
  DO_TEST(params_64, UINT64_MAX - 1, UINT64_MAX - 1);
  DO_TEST(params_64, UINT64_MAX - 1, UINT64_MAX);
  DO_TEST(params_64, UINT64_MAX, UINT64_MAX - 1);
  DO_TEST(params_64, UINT64_MAX, UINT64_MAX);


  // test with random input data
  for (int i = 0; i < N_TRIALS; i++) {
    int err = test_ore_blk_random();
    if (err != ERROR_NONE) {
      printf("FAIL\n");
      printf("Error: %d\n", err);
      return -1;
    }
  }

  printf("PASS\n");
  return 0;
}
