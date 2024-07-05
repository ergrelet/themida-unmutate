# themida-unmutate

[![GitHub release](https://img.shields.io/github/release/ergrelet/themida-unmutate.svg)](https://github.com/ergrelet/themida-unmutate/releases) [![Minimum Python version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/) ![CI status](https://github.com/ergrelet/themida-unmutate/actions/workflows/lint.yml/badge.svg?branch=main)

A Python 3 tool to statically deobfuscate functions protected by Themida, WinLicense and Code Virtualizer 3.x's mutation-based obfuscation.  
The tool has been **tested on Themida up to version 3.1.9**. It's expected to work on WinLicense and
Code Virtualizer as well.

## Features

- Automatically resolve trampolines' destination addresses
- Statically deobfuscate mutated functions
- Rebuild fully working binaries
- Binary Ninja integration

## Known Limitations

- Doesn't support ARM64 binaries

## How To

### Download

You can fetch the project with `git` and install it with `pip`:

```
pip install git+https://github.com/ergrelet/themida-unmutate.git
```

### Use

Here's what the CLI looks like:

```
themida-unmutate --help
usage: themida-unmutate.cmd [-h] -a ADDRESSES [ADDRESSES ...] -o OUTPUT [-v] protected_binary

Automatic deobfuscation tool for Themida's mutation-based protection

positional arguments:
  protected_binary      Protected binary path

options:
  -h, --help            show this help message and exit
  -a ADDRESSES [ADDRESSES ...], --addresses ADDRESSES [ADDRESSES ...]
                        Addresses of the functions to deobfuscate
  -o OUTPUT, --output OUTPUT
                        Output binary path
  -v, --verbose         Enable verbose logging
```

You can also find a Binary Ninja plugin in the `binja_plugin` directory.
