# FastORE

This is a prototype implementation of the order-revealing encryption (ORE) schemes
described in the following papers:
  * [Practical Order-Revealing Encryption with Limited Leakage](https://eprint.iacr.org/2015/1125.pdf) (ore.h)
  * [Order-Revealing Encryption: New Constructions, Applications, and Lower Bounds](https://eprint.iacr.org/2016/612.pdf) (ore_blk.h)

This implementation is derived from an implementation by:
  * David J. Wu, Stanford University
  * Kevin Lewi, Stanford University

Their original implementation can be found at https://github.com/kevinlewi/fastore .
Also check out their project website: https://crypto.stanford.edu/ore/ .

This implementation differs from the original one in the following respects:
  * The instantiation of the PRP has been replaced. The original code included a (known insecure?) Feistel construction.
    This implementation uses a PRP based on the Knuth shuffle, using something like AES-CTR as a PRG during shuffling.
  * Left and right ciphertexts have been separated. The code here exposes left and right ciphertexts as separate structures,
    and exposes distinct API functions for encrypting to left/right ciphertexts.
  * The (pure) comparison data of left and right ciphertexts has been augmented by a standard AES-GCM encryption of the plaintext.
    Thus, decryption no longer requires doing binary search.
    The left/right comparison data is used as "associated data" during AES-GCM encryption, hence it is authenticated.
    (But whoever is executing the comparisons can not check the authentication tag. Only the decryptor can.)
  * HMAC-SHA256 is supported as another implementation of the hash function modelled as random oracle.
    It can be enabled by setting the respective flag in flags.h.

**This implementation is a research prototype and serves primarily as a proof of concept
and benchmarking tool for the schemes implemented here. The code has not been carefully
analyzed for potential security flaws, and is not intended for use in production-level
code.**

## Prerequisites ##

Make sure you have the following installed:
 * [GMP 5](http://gmplib.org/)
 * [OpenSSL](http://www.openssl.org/source/)

Currently, the system requires a processor that supports the AES-NI instruction set.
This code was developed and tested on Ubuntu GNU/Linux 18.04.2.

For questions about this code, please contact:
  gunnar.hartung@kit.edu
For questions about the original code (and the scheme) you may wish to contact:
  dwu4@cs.stanford.edu

## Installation ##

    git clone --recursive https://domain.tld/path/fastore
    cd fastore
    make

## Running Tests ##

To test the basic ORE scheme (described in the first [paper](https://eprint.iacr.org/2015/1125.pdf)),
use the following command:

    ./tests/test_ore

To test the "block ORE" scheme (described in the second [paper](https://eprint.iacr.org/2016/612.pdf)),
use the following command:

    ./tests/test_ore_blk

## Running Benchmarks ##

To run the benchmarks, use the commands:

    ./tests/time_ore
    ./tests/time_ore_blk

## Additional Configuration ##

See `flags.h` for additional configuration changes that are possible.
