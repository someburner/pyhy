#!/usr/bin/env python3

from _libhydrogen import ffi
from _libhydrogen import lib as h

__all__ = [
    # internal
    'hydro_call_init',
    'hydro_version',
    'pyhy_version',
    'dump_keypair_hex',
    # rand
    'hydro_random_u32',
    'hydro_random_uniform',
    'hydro_random_buf',
    'hydro_random_buf_deterministic',
    'hydro_random_ratchet',
    'hydro_random_reseed',
    # hash
    'hydro_hash_keygen',
    'hydro_hash_hash',
    'hydro_hash', # hydro_hash_init, hydro_hash_update, hydro_hash_final
    # kdf
    'hydro_kdf_master_keygen',
    'hydro_kdf_derive_from_key',
    # secretbox
    'hydro_secretbox_keygen',
    'hydro_secretbox_encrypt',
    'hydro_secretbox_decrypt',
    'hydro_secretbox_probe_create',
    'hydro_secretbox_probe_verify',
    # sign
    'hydro_sign',
    'hydro_sign_keygen',
    'hydro_sign_keygen_deterministic',
    # kx
    'hydro_kx_keygen', # all
    'hydro_kx_n_1',  'hydro_kx_n_2', # N
    'hydro_kx_kk_1', 'hydro_kx_kk_2', 'hydro_kx_kk_3', # KK
    'hydro_kx_xx_1', 'hydro_kx_xx_2', 'hydro_kx_xx_3', 'hydro_kx_xx_4', # XX
    # pwhash
    'hydro_pwhash_keygen',
    'hydro_pwhash_deterministic',
    'hydro_pwhash_create',
    'hydro_pwhash_verify',
    'hydro_pwhash_derive_static_key',
    'hydro_pwhash_reencrypt',
    'hydro_pwhash_upgrade',
    # helpers
    'hydro_memzero',
    'hydro_equal',
    'hydro_bin2hex',
    'hydro_hex2bin',
    'hydro_increment',
    'hydro_compare',
    'hydro_pad',
    'hydro_unpad'
]

h.hydro_init()
__version__ =  '0.0.3'

################################################################################
# Internal utilities
################################################################################
def hydro_call_init():
    h.hydro_init()

def hydro_version():
    return 'libhydrogen v%d.%d' % (h.HYDRO_VERSION_MAJOR, h.HYDRO_VERSION_MINOR)

def pyhy_version():
    return 'pyhy v%s' % __version__

def dump_keypair_hex(pair):
    print('\ndump_keypair_hex')
    try:
        print('\tsk', bytes(pair.sk).hex())
        print('\tpk', bytes(pair.pk).hex())
    except Exception as e:
        print('ERROR: keypair must have pk, sk fields')

################################################################################
# rand
################################################################################
__all__ += [ 'hydro_random_SEED' ]
hydro_random_SEED = h.hydro_random_SEEDBYTES

def hydro_random_u32():
    num = h.hydro_random_u32()
    assert num >= 0
    return num

def hydro_random_uniform(ulimit):
    num = h.hydro_random_uniform(ulimit)
    return num

def hydro_random_buf(ct):
    assert ct > 0
    buf = ffi.new('uint8_t[]', ct)
    h.hydro_random_buf(buf, ct)
    return bytes(buf)

def hydro_random_buf_deterministic(ct, seed):
    assert ct > 0
    assert len(seed) == h.hydro_random_SEEDBYTES
    buf = ffi.new('uint8_t[]', ct)
    h.hydro_random_buf_deterministic(buf, ct, seed)
    return bytes(buf)

def hydro_random_ratchet():
    h.hydro_random_ratchet()

def hydro_random_reseed():
    h.hydro_random_reseed()

################################################################################
# hash
################################################################################
__all__ += [ 'hydro_hash_BYTES', 'hydro_hash_BYTES_MAX', 'hydro_hash_BYTES_MIN', 'hydro_hash_CONTEXTBYTES', 'hydro_hash_KEYBYTES' ]
hydro_hash_BYTES        = h.hydro_hash_BYTES
hydro_hash_BYTES_MAX    = h.hydro_hash_BYTES_MAX
hydro_hash_BYTES_MIN    = h.hydro_hash_BYTES_MIN
hydro_hash_CONTEXTBYTES = h.hydro_hash_CONTEXTBYTES
hydro_hash_KEYBYTES     = h.hydro_hash_KEYBYTES
hydro_hash_BYTES        = h.hydro_hash_BYTES

def hydro_hash_keygen():
    buf = ffi.new('uint8_t[]', h.hydro_hash_KEYBYTES)
    h.hydro_hash_keygen(buf)
    return bytes(buf)

# https://github.com/jedisct1/libhydrogen/wiki/Generic-hashing
class hydro_hash(object):
    """wrapper class for hash creation, verification"""
    def __init__(self, ctx, key):
        """Creates a hydro_hash_state object with ctx and key (both required)"""
        assert (type(ctx) == str) and (len(ctx) == 8)
        assert len(key) == hydro_hash_KEYBYTES
        self.st = ffi.new('struct hydro_hash_state *')
        h.hydro_hash_init(self.st, ctx.encode('utf8'), key)

    def update(self, m):
        mlen = len(m)
        # print('update: +%d' % mlen)
        h.hydro_hash_update(self.st, m.encode('utf8'), mlen)

    def final(self):
        """use secret key to generate a signature"""
        buf = ffi.new('uint8_t[]', h.hydro_hash_BYTES)
        h.hydro_hash_final(self.st, buf, h.hydro_hash_BYTES)
        return bytes(buf)

# int
# hydro_hash_hash(uint8_t *out, size_t out_len, const void *in_,
# size_t in_len, const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t *key);
def hydro_hash_hash(outlen, d, ctx, key=None):
    assert (type(ctx) == str) and (len(ctx) == 8)
    assert (outlen >= h.hydro_hash_BYTES_MIN) and (outlen <= hydro_hash_BYTES_MAX)
    dlen = len(d)
    buf = ffi.new('uint8_t[]', outlen)
    if key is None:
        key = ffi.NULL
    if h.hydro_hash_hash(buf, outlen, d.encode('utf8'), dlen, ctx.encode('utf8'), key) == -1:
        return None
    return bytes(buf)

################################################################################
# kdf
################################################################################
__all__ += [ 'hydro_kdf_CONTEXTBYTES', 'hydro_kdf_KEYBYTES', 'hydro_kdf_BYTES_MAX', 'hydro_kdf_BYTES_MIN' ]
hydro_kdf_CONTEXTBYTES  = h.hydro_kdf_CONTEXTBYTES
hydro_kdf_KEYBYTES      = h.hydro_kdf_KEYBYTES
hydro_kdf_BYTES_MAX     = h.hydro_kdf_BYTES_MAX
hydro_kdf_BYTES_MIN     = h.hydro_kdf_BYTES_MIN

def hydro_kdf_master_keygen():
    buf = ffi.new('uint8_t[]', h.hydro_kdf_KEYBYTES)
    h.hydro_kdf_keygen(buf)
    return bytes(buf)

def hydro_kdf_derive_from_key(subkey_len, id, ctx, master_key):
    assert ((subkey_len >= 16) and (subkey_len <= 65535))
    assert (type(ctx) == str) and (len(ctx) == 8)
    buf = ffi.new('uint8_t[]', subkey_len)
    h.hydro_kdf_derive_from_key(buf, subkey_len, id, ctx.encode('utf8'), master_key)
    return bytes(buf)

################################################################################
# Secretbox
################################################################################
__all__ += [ 'hydro_secretbox_CONTEXTBYTES', 'hydro_secretbox_HEADERBYTES', 'hydro_secretbox_KEYBYTES', 'hydro_secretbox_PROBEBYTES' ]
hydro_secretbox_CONTEXTBYTES    = h.hydro_secretbox_CONTEXTBYTES
hydro_secretbox_HEADERBYTES     = h.hydro_secretbox_HEADERBYTES
hydro_secretbox_KEYBYTES        = h.hydro_secretbox_KEYBYTES
hydro_secretbox_PROBEBYTES      = h.hydro_secretbox_PROBEBYTES

def hydro_secretbox_keygen():
    buf = ffi.new('uint8_t[]', h.hydro_secretbox_KEYBYTES)
    h.hydro_secretbox_keygen(buf)
    return bytes(buf)

def hydro_secretbox_encrypt(m, mid, ctx, key):
    assert (type(ctx) == str) and (len(ctx) == 8)
    mlen = len(m)
    buf = ffi.new('uint8_t[]', mlen + h.hydro_secretbox_HEADERBYTES)
    h.hydro_secretbox_encrypt(buf, m.encode('utf8'), mlen, mid, ctx.encode('utf8'), key)
    return bytes(buf)

def hydro_secretbox_decrypt(c, mid, ctx, key):
    assert (type(ctx) == str) and (len(ctx) == 8)
    clen = len(c)
    buf = ffi.new('uint8_t[]', clen - h.hydro_secretbox_HEADERBYTES)
    if h.hydro_secretbox_decrypt(buf, c, clen, mid, ctx.encode('utf8'), key) != 0:
        return None
    return bytes(buf)

def hydro_secretbox_probe_create(c, ctx, key):
    assert (type(ctx) == str) and (len(ctx) == 8)
    clen = len(c)
    buf = ffi.new('uint8_t[]', h.hydro_secretbox_PROBEBYTES)
    h.hydro_secretbox_probe_create(buf, c, clen, ctx.encode('utf8'), key)
    return bytes(buf)

# NOTE/TODO: appears probe verif is not that strict about clen
def hydro_secretbox_probe_verify(p, c, ctx, key):
    assert (type(ctx) == str) and (len(ctx) == 8)
    clen = len(c)
    if (h.hydro_secretbox_probe_verify(p, c, clen, ctx.encode('utf8'), key) == 0):
        return True
    return False

################################################################################
# Sign
################################################################################
__all__ += [ 'hydro_sign_BYTES', 'hydro_sign_CONTEXTBYTES', 'hydro_sign_SEEDBYTES', 'hydro_sign_PUBLICKEYBYTES', 'hydro_sign_SECRETKEYBYTES' ]
hydro_sign_BYTES          = h.hydro_sign_BYTES
hydro_sign_SEEDBYTES      = h.hydro_sign_SEEDBYTES
hydro_sign_CONTEXTBYTES   = h.hydro_sign_CONTEXTBYTES
hydro_sign_PUBLICKEYBYTES = h.hydro_sign_PUBLICKEYBYTES
hydro_sign_SECRETKEYBYTES = h.hydro_sign_SECRETKEYBYTES

def hydro_sign_keygen():
    pair = ffi.new('struct hydro_sign_keypair *')
    h.hydro_sign_keygen(pair)
    return pair

def hydro_sign_keygen_deterministic(seed):
    pair = ffi.new('struct hydro_sign_keypair *')
    h.hydro_sign_keygen_deterministic(pair, seed)
    return pair

class hydro_sign(object):
    """wrapper class for signature creation, verification"""
    def __init__(self, ctx):
        """Creates a hydro_sign_state object with (required) ctx"""
        assert (type(ctx) == str) and (len(ctx) == 8)
        self.st = ffi.new('struct hydro_sign_state *')
        h.hydro_sign_init(self.st, ctx.encode('utf8'))

    def update(self, m):
        mlen = len(m)
        # print('update: +%d' % mlen)
        h.hydro_sign_update(self.st, m.encode('utf8'), mlen)

    def final_create(self, pair):
        """use secret key to generate a signature"""
        buf = ffi.new('uint8_t[]', h.hydro_sign_BYTES)
        h.hydro_sign_final_create(self.st, buf, bytes(pair.sk))
        return bytes(buf)

    def final_verify(self, sig, pair):
        """use public key to verify a signature"""
        result = h.hydro_sign_final_verify(self.st, sig, bytes(pair.pk))
        if result != 0:
            # print('Final verify = %d' % result)
            return False
        return True

################################################################################
# kx
################################################################################
__all__ += [ 'hydro_kx_SESSIONKEYBYTES', 'hydro_kx_PUBLICKEYBYTES', 'hydro_kx_SECRETKEYBYTES', 'hydro_kx_PSKBYTES', 'hydro_kx_SEEDBYTES' ]
hydro_kx_SESSIONKEYBYTES = h.hydro_kx_SESSIONKEYBYTES
hydro_kx_PUBLICKEYBYTES  = h.hydro_kx_PUBLICKEYBYTES
hydro_kx_SECRETKEYBYTES  = h.hydro_kx_SECRETKEYBYTES
hydro_kx_PSKBYTES        = h.hydro_kx_PSKBYTES
hydro_kx_SEEDBYTES       = h.hydro_kx_SEEDBYTES

def hydro_kx_keygen():
    pass

# ----------  N  ---------- #
__all__ += [ 'hydro_kx_N_PACKET1BYTES' ]
hydro_kx_N_PACKET1BYTES = h.hydro_kx_N_PACKET1BYTES

def hydro_kx_n_1():
    pass

def hydro_kx_n_2():
    pass

# ---------- KK ----------- #
__all__ += [ 'hydro_kx_KK_PACKET1BYTES', 'hydro_kx_KK_PACKET2BYTES' ]
hydro_kx_KK_PACKET1BYTES = h.hydro_kx_KK_PACKET1BYTES
hydro_kx_KK_PACKET2BYTES = h.hydro_kx_KK_PACKET2BYTES
def hydro_kx_kk_1():
    pass

def hydro_kx_kk_2():
    pass

def hydro_kx_kk_3():
    pass

# ---------- XX ----------- #
__all__ += [ 'hydro_kx_XX_PACKET1BYTES', 'hydro_kx_XX_PACKET2BYTES', 'hydro_kx_XX_PACKET3BYTES' ]
hydro_kx_XX_PACKET1BYTES = h.hydro_kx_XX_PACKET1BYTES
hydro_kx_XX_PACKET2BYTES = h.hydro_kx_XX_PACKET2BYTES
hydro_kx_XX_PACKET3BYTES = h.hydro_kx_XX_PACKET3BYTES

def hydro_kx_xx_1():
    pass

def hydro_kx_xx_2():
    pass

def hydro_kx_xx_3():
    pass

def hydro_kx_xx_3():
    pass

def hydro_kx_xx_4():
    pass

################################################################################
# pwhash
################################################################################
__all__ += [ 'hydro_pwhash_CONTEXTBYTES', 'hydro_pwhash_MASTERKEYBYTES', 'hydro_pwhash_STOREDBYTES' ]
hydro_pwhash_CONTEXTBYTES = h.hydro_pwhash_CONTEXTBYTES
hydro_pwhash_MASTERKEYBYTES = h.hydro_pwhash_MASTERKEYBYTES
hydro_pwhash_STOREDBYTES = h.hydro_pwhash_STOREDBYTES

def hydro_pwhash_keygen():
    pass

def hydro_pwhash_deterministic():
    pass

def hydro_pwhash_create():
    pass

def hydro_pwhash_verify():
    pass

def hydro_pwhash_derive_static_key():
    pass

def hydro_pwhash_reencrypt():
    pass

def hydro_pwhash_upgrade():
    pass

################################################################################
# helpers
################################################################################
def hydro_memzero():
    pass

def hydro_equal():
    pass

def hydro_bin2hex():
    pass

def hydro_hex2bin():
    pass

def hydro_increment():
    pass

def hydro_compare():
    pass

def hydro_pad():
    pass

def hydro_unpad():
    pass

################################################################################














##### eof
