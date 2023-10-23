# Unmapper

Unmap sections mapped in memory in the memory dump of a PE using [pefile](https://github.com/erocarrera/pefile).

## Rationale

One of the key steps of unpacking malware (also known as self-injection malware) is the dumping of a region of memory. Often, this dumped region of memory (or memory dump) is mapped in memory by the loader. To design and implement a generic unpacker that scales, one key consideration is to be able to fix or unmap that memory dump.

I also want to study the PE format in depth.

## Usage

```msdos
python unmapper.py --help
usage: unmapper.py [-h] [-b BASE] [-o OUT] [-p PATH | -v] [--backup]

Unmap sections mapped in memory in the memory dump of a PE.

options:
  -h, --help            show this help message and exit
  -b BASE, --base BASE  base address in decimal or hexadecimal with '0x' prefix
  -o OUT, --out OUT     unmapped PE file name
  -p PATH, --path PATH  path to memory dump
  -v, --version         show program's version number and exit
  --backup              back up memory dump
```
