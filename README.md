# themida-unmutate

[![GitHub release](https://img.shields.io/github/release/ergrelet/themida-unmutate.svg)](https://github.com/ergrelet/themida-unmutate/releases) [![Minimum Python version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/) ![CI status](https://github.com/ergrelet/themida-unmutate/actions/workflows/lint.yml/badge.svg?branch=main)

A Python 3 tool to statically deobfuscate functions protected by Themida,
WinLicense and Code Virtualizer 3.x's mutation-based obfuscation.  
The tool has been **tested on Themida up to version 3.1.9**. It's expected to
work on WinLicense and Code Virtualizer as well.

A Binary Ninja plugin is also available [here](https://github.com/ergrelet/themida-unmutate-bn).

## Features

- Automatically resolve trampolines' destination addresses
- Statically deobfuscate mutated functions
- Rebuild fully working binaries

## Known Limitations

- Only supports x86_64 binaries

## How to Download

You can install the project with `pip`:

```
pip install themida-unmutate
```

A standalone PyInstaller build is available for Windows in "Releases".

## How to Use

Here's what the CLI looks like:

```
$ themida-unmutate --help
usage: themida-unmutate [-h] -a ADDRESSES [ADDRESSES ...] -o OUTPUT [--no-trampoline] [--reassemble-in-place] [-v] protected_binary

Automatic deobfuscation tool for Themida's mutation-based protection

positional arguments:
  protected_binary      Protected binary path

options:
  -h, --help            show this help message and exit
  -a ADDRESSES [ADDRESSES ...], --addresses ADDRESSES [ADDRESSES ...]
                        Addresses of the functions to deobfuscate
  -o OUTPUT, --output OUTPUT
                        Output binary path
  --no-trampoline       Disable function unwrapping
  --reassemble-in-place
                        Rewrite simplified code over the mutated code rather than in a new code section
  -v, --verbose         Enable verbose logging
```
