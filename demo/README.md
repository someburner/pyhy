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




### End
