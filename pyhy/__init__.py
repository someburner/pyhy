#!/usr/bin/env python3

from _libhydrogen import ffi
from _libhydrogen import lib as h

__all__ = [
    # internal
    'hydro_call_init',
    'hydro_version',
    'dump_keypair_hex',
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
    # util
    'hydro_random_buf',
    'hydro_random_ratchet',
    'hydro_random_reseed'
]

# __all__ += [
# 'tmp'
# ]

h.hydro_init()

################################################################################
# Internal utilities
################################################################################
def hydro_call_init():
    h.hydro_init()

def hydro_version():
    return 'libhydrogen v%d.%d' % (h.HYDRO_VERSION_MAJOR, h.HYDRO_VERSION_MINOR)

def dump_keypair_hex(pair):
    print('\ndump_keypair_hex')
    try:
        print('\tsk', bytes(pair.sk).hex())
        print('\tpk', bytes(pair.pk).hex())
    except Exception as e:
        print('ERROR: keypair must have pk, sk fields')

################################################################################
# kdf
################################################################################
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
# Utilities
################################################################################
def hydro_random_buf(ct):
    assert ct > 0
    buf = ffi.new('uint8_t[]', ct)
    h.hydro_random_buf(buf, ct)
    return bytes(buf)

def hydro_random_ratchet():
    h.hydro_random_ratchet()

def hydro_random_reseed():
    h.hydro_random_reseed()

################################################################################
__version__ =  '0.0.2'














##### eof
