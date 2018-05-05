#!/usr/bin/env python3

from pyhy import *
import sys
import binascii

TEST_CTX = 'test1234'
FAIL_CTX = '1234test'
INVALID_CTX = '123456789'
STATIC_MASTER_KEY = bytes(b'\x82\xb8\x22\x0b\x8b\xb1\xf3\x2b\x63\x68\x9c\xca\x0f\x73\x86\xc3\x7a\x09\xbf\x76\xbd\x66\xf0\xca\x40\x17\x62\x94\x7a\x93\x92\x22')

################################################################################
# hashing - TODO
################################################################################


################################################################################
# kdf
################################################################################
def test_kdf():
    print('\ntest_kdf')
    master_key = hydro_kdf_master_keygen()
    assert len(master_key) == 32
    bad_master_key = hydro_kdf_master_keygen()
    # print('Master key:', master_key.hex())
    subkey1 = hydro_kdf_derive_from_key(16, 0, TEST_CTX, master_key)
    assert len(subkey1) == 16
    subkey2 = hydro_kdf_derive_from_key(16, 0, TEST_CTX, master_key)
    assert subkey1 == subkey2
    subkey2 = hydro_kdf_derive_from_key(16, 0, FAIL_CTX, master_key)
    assert subkey1 != subkey2
    subkey2 = hydro_kdf_derive_from_key(16, 1, TEST_CTX, master_key)
    assert subkey1 != subkey2
    subkey2 = hydro_kdf_derive_from_key(16, 0, TEST_CTX, bad_master_key)
    assert subkey1 != subkey2
    subkey2 = hydro_kdf_derive_from_key(32, 0, TEST_CTX, master_key)
    assert subkey1 != subkey2
    assert len(subkey2) == 32
    bunch_of_subkeys = []
    for i in range(0, 1024):
        subkey_n = hydro_kdf_derive_from_key(16, i, TEST_CTX, master_key)
        assert subkey_n not in bunch_of_subkeys
        bunch_of_subkeys.append(subkey_n)
    subkey1_again = hydro_kdf_derive_from_key(16, 0, TEST_CTX, master_key)
    assert subkey1 == subkey1_again
    return

################################################################################
# Secretbox
################################################################################
TEST_TEXT = 'This is a test'
FAIL_TEXT = 'This is not a test'

def assert_plaintext(ptxt, check_txt):
    if (ptxt is None) or (ptxt.decode() != check_txt):
        raise Exception('failed to decrypt')
    print('Decrypted plaintext: ', ptxt)

def test_secretbox():
    print('\ntest_secretbox')
    goodkey = hydro_secretbox_keygen()
    # print('Generated key:', key.hex())
    ctxt = hydro_secretbox_encrypt(TEST_TEXT, 0, TEST_CTX, goodkey)
    # print('Ciphertext: ', ctxt.hex())
    #### pass case
    ptxt = hydro_secretbox_decrypt(ctxt, 0, TEST_CTX, goodkey)
    assert_plaintext(ptxt, TEST_TEXT)
    #### some fail cases
    badkey = hydro_secretbox_keygen()
    ptxt = hydro_secretbox_decrypt(ctxt, 0, TEST_CTX, badkey)
    assert ptxt is None, 'ptxt should be None'
    ptxt = hydro_secretbox_decrypt(ctxt, 0, FAIL_CTX, goodkey)
    assert ptxt is None, 'ptxt should be None'
    return

def test_secretbox_probes():
    print('\ntest_secretbox_probes')
    key = hydro_secretbox_keygen()
    ctxt = hydro_secretbox_encrypt('This is a test', 0, TEST_CTX, key)
    probe = hydro_secretbox_probe_create(ctxt, TEST_CTX, key)
    # print('Generated probe:', probe.hex())
    assert hydro_secretbox_probe_verify(probe, ctxt, TEST_CTX, key) == True, 'probe verification failed'
    print('probe verified')

################################################################################
# Sign
################################################################################
def test_signature_pass():
    print('\ntest_signature')
    kp = hydro_sign_keygen()
    ss1 = hydro_sign(TEST_CTX)
    ss1.update('first chunk')
    ss1.update('second chunk')
    sig = ss1.final_create(kp)
    # print('Signature: ', sig.hex())

    ss2 = hydro_sign(TEST_CTX)
    ss2.update('first chunk')
    ss2.update('second chunk')
    assert ss2.final_verify(sig, kp) == True, 'signature verification failed'
    print('OK: signature verified')

def test_signature_fail():
    print('\ntest_signature_fail')
    kp = hydro_sign_keygen()
    ss1 = hydro_sign(TEST_CTX)
    ss1.update('first chunk')
    ss1.update('second chunk')
    sig = ss1.final_create(kp)
    # print('Signature: ', sig.hex())

    ss2 = hydro_sign(TEST_CTX)
    ss2.update('first chunk')
    ss2.update('second chunk')
    ss2.update('third chunk weeeee')
    assert ss2.final_verify(sig, kp) == False, 'signature verification should have failed'
    print('OK: signature verification failed')


################################################################################
# kx - TODO
################################################################################


################################################################################
# other
################################################################################
def test_other():
    # context integrity checks
    try: oops = hydro_sign(INVALID_CTX)
    except Exception as e: print('Bad ctx len assertion ok')
    try: oops = hydro_sign(1234)
    except Exception as e: print('Bad ctx type assertion ok')
    hydro_random_ratchet()
    hydro_random_reseed()

################################################################################
# Init
################################################################################

def main():
    # wrapper
    print( hydro_version() )
    test_other()
    # kdf
    test_kdf()
    # secretbox
    test_secretbox()
    test_secretbox_probes()
    # sign
    test_signature_pass()
    test_signature_fail()
    # kx - n
    # kx - kk
    # kx - xx
    return


if __name__ == '__main__':
    main()


sys.exit(0)
