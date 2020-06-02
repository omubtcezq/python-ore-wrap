"""
Author: 
Marko Ristic

Synopsis:
Python wrapper for C implementation of Lewi Left-Right Order Revealing Encryption
Example usage:

sk = OREBlkSecretKey()
e1 = OREBlkCiphertext(sk, 'L', 12)
e2 = OREBlkCiphertext(sk, 'R', 17)
print(e1 < e2)
"""


import ctypes as ct
from ctypes.util import find_library


# Load library dependencies first
ssl = ct.CDLL(find_library('ssl'), mode=ct.RTLD_GLOBAL)
gmp = ct.CDLL(find_library('gmp'), mode=ct.RTLD_GLOBAL)
crypto = ct.CDLL(find_library('crypto'), mode=ct.RTLD_GLOBAL)
ore_crypto = ct.CDLL("ore/libbuild/crypto.so", mode=ct.RTLD_GLOBAL)
# Load the the ORE library
ore_blk = ct.CDLL("ore/libbuild/ore_blk.so")


class OREBlkError(Exception):
    """Raised when ORE Blk wrapper throws an exception."""
    pass

class OREBlk:
    """Base class for all ORE classes, provides error checking for C function return values."""
    def err_check(self, code, msg):
        if code != 0:
            raise OREBlkError("ORE Error! Code: %d. %s" % (code, msg))

class OREBlkSecretKey(OREBlk):
    """ORE secret key class. Creates and stores the encryption scheme parameters and secret key."""
    # Hack to avoid having to define complicated types in python ctypes. Since data does not need to be read, treat types as byte arrays.
    # Below are the sizeof(...) returns when run on the types in C.
    ORE_BLK_PARAMS_SIZE = 12
    ORE_BLK_SECRET_KEY_SIZE = 56
    Ore_blk_secret_key = ct.c_byte * ORE_BLK_SECRET_KEY_SIZE
    Ore_blk_params = ct.c_byte * ORE_BLK_PARAMS_SIZE

    def __init__(self, nbits=64, block_len=8):
        c_nbits = ct.c_uint32(nbits)
        c_block_len = ct.c_uint32(block_len)

        params = OREBlkSecretKey.Ore_blk_params()
        err_msg = "Could not initialise parameters."
        self.err_check(ore_blk.init_ore_blk_params(ct.byref(params),c_nbits,c_block_len), err_msg)
        self._params = params

        sk = OREBlkSecretKey.Ore_blk_secret_key()
        err_msg = "Could not initialise secret key."
        self.err_check(ore_blk.ore_blk_setup(ct.byref(sk), ct.byref(self._params)), err_msg)
        self._key = sk
        return
    
    def get_params(self):
        return self._params
    
    def get_key(self):
        return self._key

class OREBlkCiphertext(OREBlk):
    """ORE ciphertext class. Creates either a Left or Right encryption, and implements Python magic methods for their comparison."""
    # Hack to avoid having to define complicated types in python ctypes. Since data does not need to be read, treat types as byte arrays.
    # Below are the sizeof(...) returns when run on the types in C.
    ORE_BLK_CIPHERTEXT_LEFT_SIZE = 72
    ORE_BLK_CIPHERTEXT_RIGHT_SIZE = 72
    Ore_blk_ciphertext_left = ct.c_byte * ORE_BLK_CIPHERTEXT_LEFT_SIZE
    Ore_blk_ciphertext_right = ct.c_byte * ORE_BLK_CIPHERTEXT_RIGHT_SIZE

    def __init__(self, ore_blk_secret_key, enc_type, num):
        if enc_type == 'L' or enc_type == 'R':
            self._enc_type = enc_type
        else:
            raise OREBlkError('Unknown ORE encryption type "%s". Suppoted types are "L" and "R".' % enc_type)

        if self._enc_type == 'L':
            enc = OREBlkCiphertext.Ore_blk_ciphertext_left()
            val = ct.c_uint64(num)

            err_msg = "Could not initialise left ciphertext."
            self.err_check(ore_blk.init_ore_blk_ciphertext_left(ct.byref(enc), ct.byref(ore_blk_secret_key.get_params())), err_msg)
            err_msg = "Could not encrypt left ciphertext."
            self.err_check(ore_blk.ore_blk_encrypt_ui_left(ct.byref(enc), ct.byref(ore_blk_secret_key.get_key()), val), err_msg)
        
        else:
            enc = OREBlkCiphertext.Ore_blk_ciphertext_right()
            val = ct.c_uint64(num)

            err_msg = "Could not initialise right ciphertext."
            self.err_check(ore_blk.init_ore_blk_ciphertext_right(ct.byref(enc), ct.byref(ore_blk_secret_key.get_params())), err_msg)
            err_msg = "Could not encrypt right ciphertext."
            self.err_check(ore_blk.ore_blk_encrypt_ui_right(ct.byref(enc), ct.byref(ore_blk_secret_key.get_key()), val), err_msg)

        self._encryption = enc
        return
    
    def get_enc_type(self):
        return self._enc_type
    
    def _check_comparable(self, other):
        if not isinstance(other, OREBlkCiphertext):
            raise OREBlkError('Comparison only supported between instances of "OREBlkCiphertext". Given instance of "%s".' % other.__class__)
        if self._enc_type not in ['L', 'R'] or other._enc_type not in ['L', 'R']:
            raise OREBlkError('Encryption type not recognised. Ecnryption types given are "%s" and "%s".' % (self._enc_type, other._enc_type))
        if self._enc_type == other._enc_type:
            raise OREBlkError('Comparison not supported between encryptions of the same type. Both encryption are of type "%s".' % self._enc_type)
    
    def _cmp(self, other):
        cmp_val = ct.c_int(0)
        err_msg = "Could not compare ciphertexts."
        if self._enc_type == 'L':
            self.err_check(ore_blk.ore_blk_compare(ct.byref(cmp_val), ct.byref(self._encryption), ct.byref(other._encryption)), err_msg)
        else:
            self.err_check(ore_blk.ore_blk_compare(ct.byref(cmp_val), ct.byref(other._encryption), ct.byref(self._encryption)), err_msg)
        return cmp_val.value

    def __eq__(self, other):
        self._check_comparable(other)
        return self._cmp(other) == 0
    
    def __lt__(self, other):
        self._check_comparable(other)
        return self._cmp(other) < 0
    
    def __gt__(self, other):
        self._check_comparable(other)
        return self._cmp(other) > 0



