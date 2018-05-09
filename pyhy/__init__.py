#!/usr/bin/env python3

from _libhydrogen import ffi
from _libhydrogen import lib as h

# Documentation:
# https://github.com/jedisct1/libhydrogen/wiki

__all__ = [
    # internal
    'hydro_call_init',
    'hydro_version',
    'pyhy_version',
    'dump_keypair_hex',
    'dump_session_keypair_hex',
    'hexify',
    'unhexify',
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
    'hydro_kx_keygen',
    'hydro_kx_keygen_deterministic',
    'hydro_kx_keypair', 'hydro_kx_session_keypair',
    # kx - NOISE_N
    'hydro_kx_n_1',  'hydro_kx_n_2',
    # kx - NOISE_KK
    'hydro_kx_kk_1', 'hydro_kx_kk_2', 'hydro_kx_kk_3',
    'hydro_kx_kk_client',
    # kx - NOISE_XX
    'hydro_kx_xx_1', 'hydro_kx_xx_2', 'hydro_kx_xx_3', 'hydro_kx_xx_4',
    'hydro_kx_xx_client', 'hydro_kx_xx_server',
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
__version__ =  '0.0.6'

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

def dump_session_keypair_hex(pair):
    print('\ndump_session_keypair_hex')
    try:
        print('\ttx', bytes(pair.tx).hex())
        print('\trx', bytes(pair.rx).hex())
    except Exception as e:
        print('ERROR: keypair must have tx, rx fields')

def hexify(s):
    return ''.join('%02X' % c for c in s)

def unhexify(hs):
    s = bytes()
    for i in range(0, len(hs) - 1, 2):
        hex_string = hs[i:i + 2]
        s += bytes([int(hex_string, 16)])
    return s

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
        assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
        assert len(key) == h.hydro_hash_KEYBYTES
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
    assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
    assert (outlen >= h.hydro_hash_BYTES_MIN) and (outlen <= h.hydro_hash_BYTES_MAX)
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
    assert ((subkey_len >= h.hydro_kdf_BYTES_MIN) and (subkey_len <= h.hydro_kdf_BYTES_MAX))
    assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
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
    assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
    mlen = len(m)
    if not mlen:
        return bytes(0)
    buf = ffi.new('uint8_t[]', mlen + h.hydro_secretbox_HEADERBYTES)
    h.hydro_secretbox_encrypt(buf, m.encode('utf8'), mlen, mid, ctx.encode('utf8'), key)
    return bytes(buf)

def hydro_secretbox_decrypt(c, mid, ctx, key):
    assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
    clen = len(c)
    if clen <= h.hydro_secretbox_HEADERBYTES:
        return None
    buf = ffi.new('uint8_t[]', clen - h.hydro_secretbox_HEADERBYTES)
    if h.hydro_secretbox_decrypt(buf, c, clen, mid, ctx.encode('utf8'), key) != 0:
        return None
    return bytes(buf)

def hydro_secretbox_probe_create(c, ctx, key):
    assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
    clen = len(c)
    buf = ffi.new('uint8_t[]', h.hydro_secretbox_PROBEBYTES)
    h.hydro_secretbox_probe_create(buf, c, clen, ctx.encode('utf8'), key)
    return bytes(buf)

# NOTE/TODO: appears probe verif is not that strict about clen
def hydro_secretbox_probe_verify(p, c, ctx, key):
    assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
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
    pair = ffi.new('hydro_sign_keypair *')
    h.hydro_sign_keygen(pair)
    return pair

def hydro_sign_keygen_deterministic(seed):
    pair = ffi.new('hydro_sign_keypair *')
    h.hydro_sign_keygen_deterministic(pair, seed)
    return pair

class hydro_sign(object):
    """wrapper class for signature creation, verification"""
    def __init__(self, ctx):
        """Creates a hydro_sign_state object with (required) ctx"""
        assert (type(ctx) == str) and (len(ctx) == h.hydro_kdf_CONTEXTBYTES)
        self.st = ffi.new('hydro_sign_state *')
        h.hydro_sign_init(self.st, ctx.encode('utf8'))

    def update(self, m):
        mlen = len(m)
        # print('update: +%d' % mlen)
        h.hydro_sign_update(self.st, m.encode('utf8'), mlen)

    def final_create(self, secret_key, wipe=True):
        """use secret key to generate a signature"""
        buf = ffi.new('uint8_t[]', h.hydro_sign_BYTES)
        h.hydro_sign_final_create(self.st, buf, secret_key)
        if wipe:
            hydro_memzero(secret_key)
        return bytes(buf)

    def final_verify(self, sig, public_key):
        """use public key to verify a signature"""
        # print('final_verify %s' % str(dir(public_key)))
        result = h.hydro_sign_final_verify(self.st, sig, public_key)
        if result != 0:
            # print('Final verify = %d' % result)
            return False
        return True

################################################################################
# kx
# NOTE: These support optional pre-shared secret keys
# - If psk is not NULL, the same value has to be used with all functions
#   involved in the key exchange, and be the same for both client and server
# - In variants accepting anonymous clients, the PSK can be useful to restrict
#   access to a set of clients knowing this extra key
# - In variants requiring more than a single round-trip, the PSK can be useful
#   to avoid extra round trips on unsuccessful authentication attempts
################################################################################
__all__ += [ 'hydro_kx_SESSIONKEYBYTES', 'hydro_kx_PUBLICKEYBYTES', 'hydro_kx_SECRETKEYBYTES', 'hydro_kx_PSKBYTES', 'hydro_kx_SEEDBYTES' ]
hydro_kx_SESSIONKEYBYTES = h.hydro_kx_SESSIONKEYBYTES
hydro_kx_PUBLICKEYBYTES  = h.hydro_kx_PUBLICKEYBYTES
hydro_kx_SECRETKEYBYTES  = h.hydro_kx_SECRETKEYBYTES
hydro_kx_PSKBYTES        = h.hydro_kx_PSKBYTES
hydro_kx_SEEDBYTES       = h.hydro_kx_SEEDBYTES

def hydro_kx_keygen():
    pair = ffi.new('hydro_kx_keypair *')
    h.hydro_kx_keygen(pair)
    return pair

def hydro_kx_keygen_deterministic(seed):
    pair = ffi.new('hydro_kx_keypair *')
    h.hydro_kx_keygen_deterministic(pair, seed)
    return pair

# Create a hydro_kx_keypair from pk/sk bytes
# uint8_t pk[hydro_kx_PUBLICKEYBYTES];
# uint8_t sk[hydro_kx_SECRETKEYBYTES];
def hydro_kx_keypair(pk_bytes, sk_bytes):
    assert len(pk_bytes) == h.hydro_kx_PUBLICKEYBYTES
    assert len(sk_bytes) == h.hydro_kx_SECRETKEYBYTES
    pair = ffi.new('hydro_kx_keypair *')
    ffi.memmove(pair.pk, pk_bytes, h.hydro_kx_PUBLICKEYBYTES)
    ffi.memmove(pair.sk, sk_bytes, h.hydro_kx_SECRETKEYBYTES)
    return pair

# Create a hydro_kx_session_keypair from tx/rx bytes
# uint8_t tx[hydro_kx_SESSIONKEYBYTES];
# uint8_t rx[hydro_kx_SESSIONKEYBYTES];
def hydro_kx_session_keypair(tx_bytes, rx_bytes):
    assert len(tx_bytes) == h.hydro_kx_SESSIONKEYBYTES
    assert len(rx_bytes) == h.hydro_kx_SESSIONKEYBYTES
    session_pair = ffi.new('hydro_kx_session_keypair *')
    ffi.memmove(session_pair.tx, tx_bytes, h.hydro_kx_SESSIONKEYBYTES)
    ffi.memmove(session_pair.rx, rx_bytes, h.hydro_kx_SESSIONKEYBYTES)
    return session_pair

# ------------------------------------ N ------------------------------------- #
__all__ += [ 'hydro_kx_N_PACKET1BYTES' ]
hydro_kx_N_PACKET1BYTES = h.hydro_kx_N_PACKET1BYTES

def hydro_kx_n_1(server_pubkey, psk=None):
    """client: generate session keys + packet with pubkey"""
    if psk is None:
        psk = ffi.NULL
    session_kp_client = ffi.new('hydro_kx_session_keypair *')
    packet1 = ffi.new('uint8_t[]', h.hydro_kx_N_PACKET1BYTES)
    if (h.hydro_kx_n_1(session_kp_client, packet1, psk, server_pubkey) != 0):
        return (None, None)
    return (session_kp_client, bytes(packet1))

def hydro_kx_n_2(kp, pkt1, psk=None):
    if psk is None:
        psk = ffi.NULL
    session_kp_server = ffi.new('hydro_kx_session_keypair *')
    if (h.hydro_kx_n_2(session_kp_server, pkt1, psk, kp) != 0):
        return None
    return session_kp_server
# ---------------------------------------------------------------------------- #


# ------------------------------------ KK ------------------------------------ #
__all__ += [ 'hydro_kx_KK_PACKET1BYTES', 'hydro_kx_KK_PACKET2BYTES' ]
hydro_kx_KK_PACKET1BYTES = h.hydro_kx_KK_PACKET1BYTES
hydro_kx_KK_PACKET2BYTES = h.hydro_kx_KK_PACKET2BYTES

def hydro_kx_kk_1(st_client, server_pubkey, client_kp):
    pkt1 = ffi.new('uint8_t[]', h.hydro_kx_KK_PACKET1BYTES)
    if (h.hydro_kx_kk_1(st_client, pkt1, server_pubkey, client_kp) != 0):
        return None
    return bytes(pkt1)

def hydro_kx_kk_2(pkt1, client_pubkey, server_kp):
    pkt2 = ffi.new('uint8_t[]', h.hydro_kx_KK_PACKET2BYTES)
    session_kp_server = ffi.new('hydro_kx_session_keypair *')
    if (h.hydro_kx_kk_2(session_kp_server, pkt2, pkt1, client_pubkey, server_kp) != 0):
        return (None, None)
    return (session_kp_server, bytes(pkt2))

def hydro_kx_kk_3(st_client, pkt2, server_pubkey):
    session_kp_client = ffi.new('hydro_kx_session_keypair *')
    if (h.hydro_kx_kk_3(st_client, session_kp_client, pkt2, server_pubkey) != 0):
        return None
    return session_kp_client

# ------------------------------- KK (helpers) ------------------------------- #
class hydro_kx_kk_client(object):
    """wrapper class for client for kk-type kx"""
    def __init__(self):
        self.st = ffi.new('hydro_kx_state *')

    def kk_1(self, server_pubkey, client_kp):
        return hydro_kx_kk_1(self.st, server_pubkey, client_kp)

    def kk_3(self, pkt2, server_pubkey):
        return hydro_kx_kk_3(self.st, pkt2, server_pubkey)
# ---------------------------------------------------------------------------- #


# ------------------------------------ XX ------------------------------------ #
__all__ += [ 'hydro_kx_XX_PACKET1BYTES', 'hydro_kx_XX_PACKET2BYTES', 'hydro_kx_XX_PACKET3BYTES' ]
hydro_kx_XX_PACKET1BYTES = h.hydro_kx_XX_PACKET1BYTES
hydro_kx_XX_PACKET2BYTES = h.hydro_kx_XX_PACKET2BYTES
hydro_kx_XX_PACKET3BYTES = h.hydro_kx_XX_PACKET3BYTES

def hydro_kx_xx_1(st_client, psk=None):
    """Client: initiate a key exchange"""
    if psk is None:
        psk = ffi.NULL
    pkt1 = ffi.new('uint8_t[]', h.hydro_kx_XX_PACKET1BYTES)
    if (h.hydro_kx_xx_1(st_client, pkt1, psk) != 0):
        return None
    return bytes(pkt1)

def hydro_kx_xx_2(st_server, pkt1, server_kp, psk=None):
    if psk is None:
        psk = ffi.NULL
    pkt2 = ffi.new('uint8_t[]', h.hydro_kx_XX_PACKET2BYTES)
    if (h.hydro_kx_xx_2(st_server, pkt2, pkt1, psk, server_kp) != 0):
        return None
    return bytes(pkt2)

def hydro_kx_xx_3(st_client, pkt2, client_kp, psk=None):
    pkt3 = ffi.new('uint8_t[]', h.hydro_kx_XX_PACKET3BYTES)
    # NOTE: peer_pk_server may optionally be set to NULL
    # It is where the client may learn of the servers pubkey
    peer_pk_server = ffi.new('uint8_t[]', h.hydro_kx_PUBLICKEYBYTES)
    session_kp_client = ffi.new('hydro_kx_session_keypair *')
    if psk is None:
        psk = ffi.NULL
    if (h.hydro_kx_xx_3(st_client, session_kp_client, pkt3, peer_pk_server, pkt2, psk, client_kp) != 0):
        return (None, None, None)
    return (session_kp_client, bytes(pkt3), bytes(peer_pk_server))

def hydro_kx_xx_4(st_server, pkt3, psk=None):
    # NOTE: peer_pk_client may optionally be set to NULL
    # It is where the server may learn of the clients pubkey
    peer_pk_client = ffi.new('uint8_t[]', h.hydro_kx_PUBLICKEYBYTES)
    session_kp_server = ffi.new('hydro_kx_session_keypair *')
    if psk is None:
        psk = ffi.NULL
    if (h.hydro_kx_xx_4(st_server, session_kp_server, peer_pk_client, pkt3, psk) != 0):
        return (None, None)
    return (session_kp_server, bytes(peer_pk_client))

# ------------------------------- XX (helpers) ------------------------------- #
class hydro_kx_xx_client(object):
    """wrapper class for client for xx-type kx"""
    def __init__(self, psk=None):
        self.psk = psk
        self.st = ffi.new('hydro_kx_state *')

    def xx_1(self):
        return hydro_kx_xx_1(self.st, self.psk)

    def xx_3(self, pkt2, client_kp):
        return hydro_kx_xx_3(self.st, pkt2, client_kp, self.psk)

class hydro_kx_xx_server(object):
    """wrapper class for server for xx-type kx"""
    def __init__(self, psk=None):
        self.psk = psk
        self.st = ffi.new('hydro_kx_state *')

    def xx_2(self, pkt1, server_kp):
        return hydro_kx_xx_2(self.st, pkt1, server_kp, self.psk)

    def xx_4(self, pkt3):
        return hydro_kx_xx_4(self.st, pkt3, self.psk)
# ---------------------------------------------------------------------------- #


################################################################################
# pwhash
################################################################################
__all__ += [ 'hydro_pwhash_CONTEXTBYTES', 'hydro_pwhash_MASTERKEYBYTES', 'hydro_pwhash_STOREDBYTES' ]
hydro_pwhash_CONTEXTBYTES = h.hydro_pwhash_CONTEXTBYTES
hydro_pwhash_MASTERKEYBYTES = h.hydro_pwhash_MASTERKEYBYTES
hydro_pwhash_STOREDBYTES = h.hydro_pwhash_STOREDBYTES

def hydro_pwhash_keygen():
    buf = ffi.new('uint8_t[]', h.hydro_pwhash_MASTERKEYBYTES)
    h.hydro_pwhash_keygen(buf)
    return bytes(buf)

def hydro_pwhash_deterministic(pw, ctx, master_key, ops_limit=10000, mem_limit=0, threads=1):
    buf = ffi.new('uint8_t[]', 32)
    pwlen = len(pw)
    h.hydro_pwhash_deterministic(buf, 32, pw.encode('utf8'), pwlen, ctx.encode('utf8'), master_key, ops_limit, mem_limit, threads)
    return bytes(buf)

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
def hydro_memzero(obj, dump_loc=False):
    if (dump_loc == True):
        print( 'hydro_memzero location: %x' % id(obj) )
    if obj is not None:
        h.hydro_memzero(obj, len(obj))

def hydro_equal(obj1, obj2, cmplen=0):
    """if len=0/not provided, assume obj comparison for equal len"""
    obj1len = len(obj1)
    obj2len = len(obj2)
    # print('len 1/2 = %d/%d' % (obj1len, obj2len))
    if not cmplen:
        if obj1len != obj2len:
            return False
        else:
            return (h.hydro_equal(obj1, obj2, len(obj1)) == 1)
    else:
        if (obj1len <= cmplen) and (obj2len <= cmplen):
            return (h.hydro_equal(obj1, obj2, cmplen) == 1)
    print('Warning: avoiding dangerous comparison')
    return False

def hydro_bin2hex():
    pass

def hydro_hex2bin():
    pass

def hydro_increment(obj):
    objlen = len(obj)
    h.hydro_increment(obj, objlen)

def hydro_compare():
    pass

def hydro_pad():
    pass

def hydro_unpad():
    pass

################################################################################














##### eof
