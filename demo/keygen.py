#!/usr/bin/env python

import shelve
import sys
import uuid

import pyhy

KEY_DB_NAME = 'keys.db'

def gen_keypair_hex():
    tmp = pyhy.hydro_kx_keygen()
    kp = {
        'pk': bytes(tmp.pk).hex(),
        'sk': bytes(tmp.sk).hex()
    }
    return kp

if __name__ == '__main__':
    print('keygen.py init')
    try:
        print('Generating kx pairs..')
        nClient = gen_keypair_hex()
        kkClient, kkServer = gen_keypair_hex(), gen_keypair_hex()
        xxClient, xxServer = gen_keypair_hex(), gen_keypair_hex()
        topic_uuid = uuid.uuid4()

        with shelve.open(KEY_DB_NAME) as db:
            db['uuid'] = str(topic_uuid)
            db['n'] = nClient
            db['kk-client'] = kkClient
            db['kk-server'] = kkServer
            db['xx-client'] = xxClient
            db['xx-server'] = xxServer
        print('Done')
    except Exception as e:
        print(e)
        print('Exception while trying to generate keys')
        print('Abort')
        sys.exit(1)

sys.exit(0)
