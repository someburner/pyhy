# pyhy

Python bindings for [libhydrogen](https://github.com/jedisct1/libhydrogen).

## Install

Requires [libhydrogen](https://github.com/jedisct1/libhydrogen) to be installed
on system. Testing/development has been done on linux, specifically Ubuntu
18.04. Additional work may be required for other platforms/distros.

```sh
pip3 install pyhy
```

## Usage

* An end-to-end example for `kx` (N, KK, XX) is provided using [paho-mqtt](https://github.com/eclipse/paho.mqtt.python).
See [demo](demo) for instructions.
* The [wiki](https://github.com/someburner/pyhy/wiki) contains a few usage
examples.
* [tests.py](https://github.com/someburner/pyhy/blob/master/test.py) is fairly
self-describing. Just copy that somewhere, run it, and hack away.

## Bindings

This project uses cffi [docs](https://cffi.readthedocs.io/en/latest/)/[bitbucket](https://bitbucket.org/cffi/cffi/issues?status=new&status=open).
If you experience low-level issues you may want to look there for help.

**Ensuring latest version**:

```sh
pip3 uninstall pyhy
pip3 install pyhy --no-cache
```

**To generate bindings yourself**:

```sh
sudo apt-get install python3-dev

virtualenv env --python=$(which python3)
source env/bin/activate
pip3 install cffi

git clone https://github.com/someburner/pyhy
cd pyhy
./bind.py
./test.py
```

**NOTE**: For development you may need to compiled/install libhydrogen with
`-fPIC` flag (add it to CFLAGS at the top of its Makefile).

## License

See LICENSE. Same as libhydrogen.
