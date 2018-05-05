# pyhy

Python bindings for [libhydrogen](https://github.com/jedisct1/libhydrogen). WIP.

## Implementation

These are implemented mostly as dumb wrappers, and follow the same usage as in
libhydrogen itself:

* `kdf`
* `secretbox`
* `helpers`
* `random`

**Things are a bit different for..**:

* `hydro_sign`
* `hydro_hash`

(See usage)

## Usage

Requires `libhydrogen` to be installed on system. Also, only tested so far on
Ubuntu 18.04. Additional work may be required for others, PRs welcome.

```sh
pip3 install pyhy
```

For `hash`/`sign` (and, likely `kx` in the future) it made more sense to create
python classes that hold the state. So instead it looks like:

```py
from pyhy import *

YOUR_CTX = 'context1'
kp = hydro_sign_keygen()
s1 = hydro_sign(YOUR_CTX)
s1.update('first chunk')
s1.update('second chunk')
sig = s1.final_create(kp.sk)
print('Signature: ', sig.hex())

s2 = hydro_sign(YOUR_CTX)
s2.update('first chunk')
s2.update('second chunk')
assert s2.final_verify(sig, kp.pk) == True
```

It also seemed natural to use python for hex conversions. You can load or
write in keys (for testing) like this:

```py
# ... hydro_sign, update, ....

your_pk_hex = '7e36d864be0145ded2912ceb05c0e66257e8db78e5eb0dd880345c842e7e1d1b'
success = s2.final_verify(sig, unhexify(your_pk_hex))
```

## Developing

**TODO**:

* rest of `pwhash`
* `kx-N`
* `kx-KK`
* `kx-XX`

**Other notes**:

This project uses cffi [docs](https://cffi.readthedocs.io/en/latest/)/[bitbucket](https://bitbucket.org/cffi/cffi/issues?status=new&status=open).

```sh
virtualenv env --python=$(which python3)
source env/bin/activate
pip3 install cffi

git clone https://github.com/someburner/pyhy.git
cd pyhy
pip3 install . --force-reinstall
# or from another location
pip3 install ../pyhy
```

## License

See LICENSE. Same as libhydrogen.
