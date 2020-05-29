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

#include "errors.h"
#include "ore_blk.h"

#include <stdio.h>
#include <time.h>

static int _err;
#define ERR_CHECK(x) if((_err = x) != ERROR_NONE) { return _err; }

/**
 * Benchmarking code for ORE scheme. Measures time to encrypt random values
 * and time to compare ORE ciphertexts. The number of iterations is scaled
 * with the approximate run-time of each operation. Measurements taken for
 * wide range of bitlengths (n) and block sizes (k).
 */
int main(int argc, char** argv) {
  const uint32_t NBITS[]            = {8, 16, 24, 32, 48, 64};
  const uint32_t BLOCK_LEN[]        = {  2,   4,   6,   8,  10,  12,  14,  16};
  const uint32_t ENC_TRIALS[]       = {400, 400, 300, 200,  80,  10,   4,   1};
  const uint32_t LEFT_DEC_TRIALS[]  = {200, 200, 200, 200, 200, 200, 200, 200};
  const uint32_t RIGHT_DEC_TRIALS[] = {400, 400, 400, 400, 400, 300, 200, 100};
  const uint32_t CMP_TRIALS[]       = {200, 200, 200, 100,  50,  25,  10,   5};

#ifdef USE_AES_RO
  const uint32_t ENC_SCALE       =   250;
  const uint32_t LEFT_DEC_SCALE  = 20000;
  const uint32_t RIGHT_DEC_SCALE =  5000;
  const uint32_t CMP_SCALE       = 50000;
#else
  const uint32_t ENC_SCALE       =    50;
  const uint32_t LEFT_DEC_SCALE  = 20000;
  const uint32_t RIGHT_DEC_SCALE =  5000;
  const uint32_t CMP_SCALE       = 20000;
#endif

  uint32_t nbits_len = sizeof(NBITS) / sizeof(int);
  uint32_t nblock_len = sizeof(BLOCK_LEN) / sizeof(int);

#ifdef USE_AES_RO
  printf("Instantiating random oracle with AES-based construction\n\n");
#else
  printf("Instantiating random oracle with SHA256\n\n");
#endif
  printf("n = bit length of plaintext space\n");
  printf("k = block size (in bits)\n\n");
  printf("%2s %2s %8s %20s %20s %8s %20s %20s %8s %20s %20s %8s %20s %20s %8s %20s %20s %20s %20s\n",
         "n", "k",
         "iter", "left enc avg (us)", "left enc total (s)",
         "iter", "right enc avg (us)", "right enc total (s)",
         "iter", "cmp avg (us)", "cmp total (s)",
         "iter", "left dec avg (us)", "left dec total (s)",
         "iter", "right dec avg (us)", "right dec total (s)",
         "len left (bytes)", "len right (bytes)");

  for (int i = 0; i < nbits_len; i++) {
    for (int j = 0; j < nblock_len; j++) {
      if (BLOCK_LEN[j] > NBITS[i]) {
        continue;
      }

      ore_blk_params params;
      ERR_CHECK(init_ore_blk_params(params, NBITS[i], BLOCK_LEN[j]));

      ore_blk_secret_key sk;
      ERR_CHECK(ore_blk_setup(sk, params));

      ore_blk_ciphertext_left ctxt1;
      ERR_CHECK(init_ore_blk_ciphertext_left(ctxt1, params));

      uint32_t n_trials = ENC_TRIALS[j] * ENC_SCALE;
      clock_t start_time = clock();
      uint32_t left_enc_trials = 0;
      while(clock() - start_time < CLOCKS_PER_SEC) {
        for (int k = 0; k < n_trials; k++) {
          ore_blk_encrypt_ui_left(ctxt1, sk, rand());
        }
        left_enc_trials += n_trials;
      }
      double left_enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
      double left_enc_time = left_enc_time_elapsed / left_enc_trials * 1000000;

      ore_blk_ciphertext_right ctxt2;
      ERR_CHECK(init_ore_blk_ciphertext_right(ctxt2, params));
      start_time = clock();
      uint32_t right_enc_trials = 0;
      while (clock() - start_time < CLOCKS_PER_SEC) {
        for (int k = 0; k < n_trials; k++) {
          ore_blk_encrypt_ui_right(ctxt2, sk, rand());
	};
        right_enc_trials += n_trials;
      };
      double right_enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
      double right_enc_time = right_enc_time_elapsed / right_enc_trials * 1000000;

      int res;

      uint32_t cmp_trials = 0;
      n_trials = CMP_TRIALS[j] * CMP_SCALE;
      start_time = clock();
      while(clock() - start_time < CLOCKS_PER_SEC) {
        for (int k = 0; k < n_trials; k++) {
         ore_blk_compare(&res, ctxt1, ctxt2);
        }
        cmp_trials += n_trials;
      }
      double cmp_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
      double cmp_time = cmp_time_elapsed / n_trials * 1000000;

      uint64_t dec_output;
      uint32_t dec_left_trials = 0;
      n_trials = LEFT_DEC_TRIALS[j] * LEFT_DEC_SCALE;
      start_time = clock();
      while(clock() - start_time < CLOCKS_PER_SEC) {
        for (int k = 0; k < n_trials; k++) {
          ore_blk_decrypt_ui_left(ctxt1, sk, &dec_output);
        }
        dec_left_trials += n_trials;
      }
      double dec_left_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
      double dec_left_time = dec_left_time_elapsed * (1000000 / (double) n_trials);

      uint32_t dec_right_trials = 0;
      n_trials = RIGHT_DEC_TRIALS[j] * RIGHT_DEC_SCALE;
      start_time = clock();
      while(clock() - start_time < CLOCKS_PER_SEC) {
        for (int k = 0; k < n_trials; k++) {
          ore_blk_decrypt_ui_right(ctxt2, sk, &dec_output);
        }
        dec_right_trials += n_trials;
      }
      double dec_right_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
      double dec_right_time = dec_right_time_elapsed * (1000000 / (double) n_trials);

      printf("%2d %2d %8d %20.2f %20.2f %8d %20.2f %20.2f %8d %20.2f %20.2f %8d %20.2f %20.2f %8d %20.2f %20.2f %20d %20d\n",
             NBITS[i], BLOCK_LEN[j],
             left_enc_trials, left_enc_time, left_enc_time_elapsed,
             right_enc_trials, right_enc_time, right_enc_time_elapsed,
             cmp_trials, cmp_time, cmp_time_elapsed,
             dec_left_trials, dec_left_time, dec_left_time_elapsed,
             dec_right_trials, dec_right_time, dec_right_time_elapsed,
             ore_blk_total_left_ciphertext_size(params), ore_blk_total_right_ciphertext_size(params)
      );

      ERR_CHECK(clear_ore_blk_ciphertext_left(ctxt1));
      ERR_CHECK(clear_ore_blk_ciphertext_right(ctxt2));
      ERR_CHECK(ore_blk_cleanup(sk));
    }
  }

  return 0;
}
