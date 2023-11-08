"""unmapper.py

Unmap sections mapped in memory in the memory dump of a PE.
"""
from argparse import ArgumentParser
from collections import Counter
from math import ceil
from os.path import abspath, basename, exists, join, splitext
from pathlib import Path
from shutil import copy2
from struct import unpack
import platform
import sys

__author__ = "limbernie"
__program__ = "Unmapper"
__version__ = "1.0"

if "Windows" not in platform.system():
    print(f"[!] {__program__} can only be run in Windows.")
    sys.exit(1)
else:
    try:
        from pefile import PE, PEFormatError, IMAGE_CHARACTERISTICS
    except ImportError:
        print("[!] Module pefile not found.")
        sys.exit(1)


class Unmapper:
    """Unmapper class."""

    def __init__(self, params: dict):
        """Unmapper constructor"""

        self.dump = params["path_to_dump"]
        try:
            self.target_pe = self.__load_pe(self.dump)
        except PEFormatError:
            print("[!] File is not in the PE format.")
            sys.exit(1)
        self.base = params["load_base_address"]
        self.out = params["unmapped_pe_file"]

    def __load_pe(self, path_to_dump: str) -> PE:
        """Load PE in path to dump."""
        pe = PE(path_to_dump)

        return pe

    def __find_base(self, target_pe: PE = None) -> int:
        """Find base address of image from relocs."""

        if target_pe is None:
            target_pe = self.target_pe

        if not target_pe.has_relocs():
            return target_pe.OPTIONAL_HEADER.ImageBase

        relocs = target_pe.DIRECTORY_ENTRY_BASERELOC
        mapped = target_pe.get_memory_mapped_image()
        entries = []

        mask = ~0xFFFF

        if self.__is_32bit():
            mask &= 0xFFFF0000
            size = 0x4
            fmtstr = "<I"
        else:
            mask &= 0xFFFFFF0000
            size = 0x8
            fmtstr = "<Q"

        for reloc in relocs:
            for entry in reloc.entries:
                entries.append(
                    unpack(fmtstr, mapped[entry.rva : entry.rva + size])[0] & mask
                )

        # Count relocation entries with mask on
        count = Counter(entries)

        # Entries with count more than pivot
        pivot = 15
        if count.most_common(1)[-1][1] > pivot:
            count = Counter({k: c for k, c in count.items() if c > pivot})
            guess = min(k for (k, c) in count.most_common() if k != 0)
        else:
            guess = count.most_common(1)[-1][0]

        pivot = 0x10000

        return (guess - pivot) if (guess & 0xF0000) == pivot else guess

    def __is_32bit(self, target_pe: PE = None) -> bool:
        """Check if target PE is 32-bit."""

        if target_pe is None:
            target_pe = self.target_pe

        is_32bit = False
        flag = IMAGE_CHARACTERISTICS["IMAGE_FILE_32BIT_MACHINE"]

        if target_pe.FILE_HEADER.Characteristics & flag == flag:
            is_32bit = True

        return is_32bit

    def __virtual_to_raw__(self) -> None:
        """Implementation of hasherezade's PE_VIRTUAL_TO_RAW mode in libpeconv."""

        with open(self.dump, "rb") as file:
            dump = file.read()

        # pylint: disable=no-member
        optional_header = self.target_pe.OPTIONAL_HEADER
        alignment = optional_header.FileAlignment
        headers_size = optional_header.SizeOfHeaders

        out = bytearray(dump[:headers_size])

        for section in self.target_pe.sections:
            raw_ptr = section.PointerToRawData
            raw_size = section.SizeOfRawData
            vir_addr = section.VirtualAddress
            vir_size = section.Misc_VirtualSize

            if ceil(vir_size / alignment) * alignment >= raw_size:
                new_size = raw_size

            sec = dump[vir_addr : vir_addr + new_size]

            out[raw_ptr : raw_ptr + raw_size] = sec

        self.target_pe = PE(data=out)

        if self.base == 0:
            rebase = self.__find_base()
            print("[!] No base address is provided. Guessing from relocs...")
            print(f"[*] Found image base: 0x{rebase:X}")
            self.base = rebase

        self.target_pe.OPTIONAL_HEADER.ImageBase = self.base

    def __write_to_file__(self, unmapped_pe_file: str) -> None:
        """Write modifed PE to file."""

        path = abspath(self.dump).removesuffix(basename(self.dump))
        fname, fext = splitext(basename(self.dump))
        fext = ".bin" if fext == "" else fext
        filename = (
            f"{fname}_unmapped{fext}" if unmapped_pe_file is None else unmapped_pe_file
        )

        if self.is_unmapped():
            self.target_pe.write(filename=f"{join(path, filename)}")
            print(f'[*] Successfully unmapped "{basename(self.dump)}" to "{filename}".')
        else:
            print("[!] Unmapping failed.")
            sys.exit(1)

    def backup(self):
        """Make a backup of the memory dump."""

        copy2(self.dump, f"{self.dump}.bak")
        filename = basename(self.dump)

        print(f'[*] File "{filename}" is backed up to "{filename}.bak".')

    def is_unmapped(self, target_pe=None):
        """Check if target PE is unmapped."""

        if target_pe is None:
            target_pe = self.target_pe

        unmapped = False

        unmapped_exports = False
        try:
            exports = target_pe.DIRECTORY_ENTRY_EXPORT
            if exports is not None:
                unmapped_exports = True
        except AttributeError:
            pass

        unmapped_imports = False
        try:
            imports = target_pe.DIRECTORY_ENTRY_IMPORT
            if imports is not None:
                unmapped_imports = True
        except AttributeError:
            pass

        if unmapped_exports or unmapped_imports:
            unmapped = True

        return unmapped

    def unmap(self):
        """Unmap memory dump."""

        self.__virtual_to_raw__()
        self.__write_to_file__(self.out)


def main():
    """Entry point"""

    parser = ArgumentParser(
        description="Unmap sections mapped in memory in the memory dump of a PE."
    )
    parser.add_argument(
        "-b",
        "--base",
        default=0,
        type=lambda x: int(x, 0),
        help="base address in decimal or hexadecimal with '0x' prefix",
    )
    parser.add_argument("-o", "--out", help="unmapped PE file name")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--path", type=Path, help="path to memory dump")
    group.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"{__program__} {__version__} by {__author__}",
    )
    parser.add_argument("--backup", action="store_true", help="back up memory dump")

    args = parser.parse_args()

    if args.path:
        if not exists(args.path):
            print(f'[!] Path to file "{args.path}"" does not exists.')
            sys.exit(1)
        params = {
            "path_to_dump": abspath(args.path),
            "load_base_address": args.base,
            "unmapped_pe_file": args.out,
        }
        unmapper = Unmapper(params)
        if unmapper.is_unmapped():
            print(f'[!] File "{basename(args.path)}" appears to be already unmapped.')
            sys.exit()
        else:
            if args.backup:
                unmapper.backup()
            unmapper.unmap()
    else:
        parser.print_usage()


if __name__ == "__main__":
    main()
