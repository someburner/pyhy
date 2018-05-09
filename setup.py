#!/usr/bin/env python
from setuptools import find_packages, setup

NAME = 'pyhy'
VERS = '0.0.6'
PACKAGES = [ 'pyhy' ]
SHORT_DESC = 'bindings for libhydrogen using cffi'
LONG_DESC = """Python bindings for libhydrogen, a small cryptographic library
suited for embedded systems requiring a low footprint. Uses cffi.
"""
KEYWORDS = [ 'cryptography', 'crypto', 'embedded', 'encryption', 'libhydrogen', 'hydrogen' ]
# http://pypi.python.org/pypi?%3Aaction=list_classifiers
CLASSIFIERS = [
    'Development Status :: 3 - Alpha',
    'License :: OSI Approved :: ISC License (ISCL)',
    'Intended Audience :: Developers',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Topic :: Security',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Embedded Systems'
]

# https://packaging.python.org/tutorials/distributing-packages/#setup-py
# https://github.com/pypa/sampleproject/blob/master/setup.py
if __name__ == '__main__':
    setup(
        name=NAME,
        version=VERS,
        description=SHORT_DESC,
        long_description=LONG_DESC,
        license='BSD',
        url='https://github.com/someburner/pyhy',
        author='Jeff Hufford',
        author_email='jeffrey92@gmail.com',
        maintainer='Jeff Hufford',
        keywords=KEYWORDS,
        classifiers=CLASSIFIERS,
        python_requires='>=3.4',
        setup_requires=["cffi>=1.0.0"],
        cffi_modules=["./bind.py:ffibuilder"],
        install_requires=["cffi>=1.0.0"],
        include_package_data=True,
        packages=['', 'pyhy'],
        package_data={
            '': [ '*.h' ],
            'pyhy': [ './*.py' ]
        }
    )
