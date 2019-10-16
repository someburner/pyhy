#!/usr/bin/env python
import os
from codecs import open
from setuptools import setup

NAME = 'pyhy'
PACKAGES = [ 'pyhy' ]
SHORT_DESC = 'bindings for libhydrogen using cffi'
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

about = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'pyhy', '__version__.py'), 'r', 'utf-8') as f:
    exec(f.read(), about)

with open('README.md', 'r', 'utf-8') as f:
    readme = f.read()

# https://packaging.python.org/tutorials/distributing-packages/#setup-py
# https://github.com/pypa/sampleproject/blob/master/setup.py
if __name__ == '__main__':
    setup(
        name=NAME,
        version=about['__version__'],
        description=SHORT_DESC,
        long_description=readme,
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
        packages=PACKAGES,
        package_data={
            'pyhy': [ './*.py' ]
        }
    )
