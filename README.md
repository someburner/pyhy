# pyhy

Python bindings for [libhydrogen](https://github.com/jedisct1/libhydrogen). WIP-
so far most of the `hydro_secretbox_xx`, `hydro_sign_xx`, and `hydro_kdf_xx`
methods are implemented.

This project uses cffi [docs](https://cffi.readthedocs.io/en/latest/)/[bitbucket](https://bitbucket.org/cffi/cffi/issues?status=new&status=open).

## Usage

Requires `libhydrogen` to be installed on system. Also, only tested so far on
Ubuntu 18.04. Additional work may be required for others, PRs welcome.

```sh
pip3 install pyhy
```

Will document after more testing. For now, see [test.py](test.py) for usage.


## Developing

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
