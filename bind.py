#!/usr/bin/env python3
from __future__ import absolute_import, division, print_function
import os
import cffi

ffibuilder = cffi.FFI()

ffibuilder.set_source(
    "_libhydrogen",
    """#include <hydrogen.h>""",
    libraries=['hydrogen']
)

with open(os.path.join(os.path.dirname(__file__), "pyhy.h")) as f:
    ffibuilder.cdef(f.read())

def _clean():
    for f in os.scandir():
        if f.is_file():
            if f.name.endswith('.o') or f.name.endswith('.so'):
                print('Cleaning ... %s' % f.name)
                os.remove(f.name)

if __name__ == "__main__":
    import os, sys
    _clean()
    ffibuilder.compile()

########
