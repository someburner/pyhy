# kx examples

Sample usage of kx functionality using Eclipse's [public broker](https://www.eclipse.org/paho/).

## Setup

```sh
# (activate venv if desired)
pip3 install pyhy
pip3 install paho-mqtt

# generate several sets of keys + topic UUID
./keygen.py

# Run server in one window
./demo.sh server-n

# open a new shell and run client
./demo.sh client-n
```

### kk

```sh
# Run server in one window
./demo.sh server-kk

# open a new shell and run client
./demo.sh client-kk
```

### xx

```sh
# Run server in one window
./demo.sh server-xx

# open a new shell and run client
./demo.sh client-xx
```

## Notes

* Does not handle disconnects/reconnects
* Given the nature of python, storing all the keys in `userdata` is not
recommended at all. It should be at least wiped after session keys are
established. This is proof of concept and its up to you to be safe with keys.
* `poll_client` method compares current milliseconds and sends a test payload
(once session is established) containing timestamp every `TX_DELAY_MS`.
Server responds with what was sent.
* Code is a bit ugly in order to handle all 3 types, but it should be easy to
crop the others out to see what's going on.

### End
