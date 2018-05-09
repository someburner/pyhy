#!/usr/bin/env python
import os
import sys
import shelve
import time

import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish

import pyhy

KEY_DB_NAME = 'keys.db'

MQTT_HOST = "iot.eclipse.org"
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

MQTT_AUTH = False
MQTT_USER = "user"
MQTT_PASS = "pass"

CTX = 'pyhydemo'
CHAN_TO_CLIENT = '/pyhy/%s/rx'
CHAN_TO_SERVER = '/pyhy/%s/tx'

TX_DELAY_MS = 5000

# Less confusing names, client
CLIENT_PUB_TOPIC, CLIENT_SUB_TOPIC = None, None
# Less confusing names, server
SERVER_PUB_TOPIC, CLIENT_SUB_TOPIC = None, None

def init_topics(uuid):
    global CLIENT_PUB_TOPIC, CLIENT_SUB_TOPIC
    global SERVER_PUB_TOPIC, SERVER_SUB_TOPIC
    # Less confusing names, client
    CLIENT_PUB_TOPIC = CHAN_TO_SERVER % uuid
    CLIENT_SUB_TOPIC = CHAN_TO_CLIENT % uuid
    # Less confusing names, server
    SERVER_PUB_TOPIC = CHAN_TO_CLIENT % uuid
    SERVER_SUB_TOPIC = CHAN_TO_SERVER % uuid

def on_sub_client(client, userdata, mid, granted_qos):
    print("Subscribed with qos %s, client id assigned = %s" % (str(granted_qos), str(client._client_id)))

def on_sub_server(client, userdata, mid, granted_qos):
    print("Subscribed with qos %s, client id assigned = %s" % (str(granted_qos), str(client._client_id)))

def on_connect_client(client, userdata, flags, rc):
    client.subscribe(CLIENT_SUB_TOPIC, 0)
    print('Connected (client)')
    if userdata['type'] == 'n':
        print('Client (n): Generate session kp + initial packet, using server pubkey')
        server_pubkey = pyhy.unhexify(userdata['kp']['pk'])
        session_kp_client, pkt1 = pyhy.hydro_kx_n_1(server_pubkey)
        userdata['session_kp'] = session_kp_client
        pyhy.dump_session_keypair_hex(session_kp_client)
        publish.single(CLIENT_PUB_TOPIC, pkt1, hostname=MQTT_HOST)
        userdata['established'] = True
    elif userdata['type'] == 'kk':
        print('kk not impl')
    elif userdata['type'] == 'xx':
        print('xx not impl')
    else:
        print('missing/invalid type in userdata')
        sys.exit(1)

def on_connect_server(client, userdata, flags, rc):
    client.subscribe(SERVER_SUB_TOPIC, 0)
    print('Connected (server)')

def on_msg_client(client, userdata, msg):
    if userdata['established'] == True:
        ptxt = pyhy.hydro_secretbox_decrypt(msg.payload, 0, CTX, userdata['session_kp'].rx)
        print('Rx > %s' % ptxt.decode())

def on_msg_server(client, userdata, msg):
    print('on_msg_server')
    if userdata['established'] == True:
        ptxt = pyhy.hydro_secretbox_decrypt(msg.payload, 0, CTX, userdata['session_kp'].rx)
        if ptxt is not None:
            print('Rx > %s' % ptxt.decode())
            ctxt = pyhy.hydro_secretbox_encrypt('You sent: "%s"' % ptxt.decode(), 0, CTX, userdata['session_kp'].tx)
            client.publish(SERVER_PUB_TOPIC, ctxt)
            return
    else:
        if userdata['type'] == 'n':
            pkt1 = msg.payload
            kp = pyhy.hydro_kx_keypair(
                    pk_bytes=pyhy.unhexify(userdata['kp']['pk']),
                    sk_bytes=pyhy.unhexify(userdata['kp']['sk'])
            )
            session_kp_server = pyhy.hydro_kx_n_2(kp, pkt1)
            pyhy.dump_session_keypair_hex(session_kp_server)
            userdata['session_kp'] = session_kp_server
            userdata['established'] = True
        elif userdata['type'] == 'kk':
            print('kk not impl')
        elif userdata['type'] == 'xx':
            print('xx not impl')
        else:
            print('missing/invalid type in userdata')
            sys.exit(1)

################################################################################
# Timer calls
################################################################################
prev_ms = 0

def poll_server(client):
    global prev_ms
    pass

def poll_client(client):
    global prev_ms
    now = int(round(time.time() * 1000))
    if ( (now - prev_ms) > TX_DELAY_MS ):
        prev_ms = now
        print('Client Tx')
        # print(client._userdata)
        if client._userdata['established']:
            ctxt = pyhy.hydro_secretbox_encrypt(str('Testing %d' % now), 0, CTX, client._userdata['session_kp'].tx)
            client.publish(CLIENT_PUB_TOPIC, ctxt)
    return

################################################################################
# Init
################################################################################
if __name__ == '__main__':
    mode, kxType = None, None
    mode, kxType = str(sys.argv[1]).split('-')

    if not mode in [ 'client', 'server' ]:
        print('Invalid mode "%s"' % str(mode))
        sys.exit(1)
    print('MODE = %s' % mode)

    if not kxType in [ 'n', 'kk', 'xx' ]:
        print('Invalid kx type "%s"' % str(kxType))
        sys.exit(1)
    print('KX = %s' % kxType)

    if not os.path.exists(KEY_DB_NAME):
        print('Error: %s DNE. Please generated first' % str(KEY_DB_NAME))
        sys.exit(1)

    kphex = {}
    with shelve.open(KEY_DB_NAME) as db:
        init_topics( db['uuid'] )
        if kxType == 'n':
            kphex['pk'] = db['n']['pk']
            kphex['sk'] = db['n']['sk']
        elif kxType == 'kk':
            kphex['pk'] = db['kk-client']['pk']
            kphex['sk'] = db['kk-client']['sk']
        elif kxType == 'xx':
            kphex['pk'] = db['xx-client']['pk']
            kphex['sk'] = db['xx-client']['sk']
        else:
            print('Maybe corrupted keys.db')
            kphex = None

    if kphex is None:
        sys.exit(1)

    print('Loaded keypair for kx (type %s)' % kxType)
    _userdata = {
        'kp': kphex,
        'type': kxType,
        'state': 0,
        'established': False,
        'session_kp': None
    }

    client = mqtt.Client(client_id=None, userdata=_userdata, clean_session=True)
    if MQTT_AUTH:
        client.username_pw_set(MQTT_USER, MQTT_PASS)
    if mode == 'client':
        client.on_connect = on_connect_client
        client.on_message = on_msg_client
        client.on_subscribe = on_sub_client
    else:
        client.on_connect = on_connect_server
        client.on_message = on_msg_server
        client.on_subscribe = on_sub_server

    ### Blocking
    client.connect(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
    # client.loop()
    client.loop_start()
    while True:
        if mode == 'client':
            poll_client(client)
        else:
            poll_server(client)

    ### async
    # client.connect_async(MQTT_HOST, MQTT_PORT, keepalive=MQTT_KEEPALIVE)
    # client.loop_start()


#### end
