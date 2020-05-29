import ctypes as ct
from ctypes.util import find_library


ssl = ct.CDLL(find_library('ssl'), mode=ct.RTLD_GLOBAL)
gmp = ct.CDLL(find_library('gmp'), mode=ct.RTLD_GLOBAL)
crypto = ct.CDLL(find_library('crypto'), mode=ct.RTLD_GLOBAL)
ore_crypto = ct.CDLL("ore/libbuild/crypto.so", mode=ct.RTLD_GLOBAL)
ore_blk = ct.CDLL("ore/libbuild/ore_blk.so")


nbits = ct.c_uint32(64)
block_len = ct.c_uint32(2)

class ore_blk_params(ct.Structure):
    _fields_ = [("initialized", ct.c_bool),
                ("nbits", ct.c_uint32),
                ("block_len", ct.c_uint32)]

params = ore_blk_params()

print(ore_blk.init_ore_blk_params(ct.byref(params),nbits,block_len))


sk = ct.c_void_p(None)
#ore_blk.ore_blk_setup(byref(sk),byref(params))


