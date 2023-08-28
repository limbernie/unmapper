"""unmapper.py

Unmap sections mapped in memory in the memory dump of a PE.
"""
from argparse import ArgumentParser
from math import ceil
from os.path import abspath, basename, splitext
from shutil import copy2
import sys

from pefile import PE

__author__ = "limbernie"
__program__ = "Unmapper"
__version__ = "1.0"


class Unmapper:
    """Unmapper class."""

    def __init__(self, path_to_dump, debug=False):
        self.dump = path_to_dump
        self.target_pe = PE(self.dump)
        self.debug = debug

    def backup(self):
        """Make a backup of the memory dump."""

        copy2(self.dump, f"{self.dump}.bak")
        filename = basename(self.dump)

        if self.debug:
            print(f'[*] File "{filename}" is backed up to "{filename}.bak".')

    def is_unmapped(self, target_pe=None):
        """Check if target PE is unmapped."""

        if target_pe is None:
            target_pe = self.target_pe

        unmapped = False

        try:
            imports = target_pe.DIRECTORY_ENTRY_IMPORT
            exports = target_pe.DIRECTORY_ENTRY_EXPORT

            if imports is not None or exports is not None:
                unmapped = True
        except AttributeError:
            pass
        return unmapped

    def unmap(self):
        """Unmap memory dump."""

        buffer = self.__virtual_to_raw__()
        self.__write_to_file__(buffer)

    def __virtual_to_raw__(self):
        """Implementation of hasherezade's PE_VIRTUAL_TO_RAW mode in libpeconv."""

        with open(self.dump, "rb") as file:
            dump = file.read()

        alignment = self.target_pe.OPTIONAL_HEADER.FileAlignment
        headers_size = self.target_pe.OPTIONAL_HEADER.SizeOfHeaders
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

        return out

    def __write_to_file__(self, buffer):
        """Write buffer to file."""

        unmapped_pe = PE(data=buffer)

        if self.is_unmapped(unmapped_pe):
            path = abspath(self.dump).removesuffix(basename(self.dump))
            fname, fext = splitext(basename(self.dump))
            fext = ".bin" if fext == "" else fext
            filename = f"{fname}_unmapped{fext}"
            unmapped_pe.write(filename=f"{path}{filename}")

            if self.debug:
                print(
                    f'[*] Successfully unmapped "{basename(self.dump)}" to "{filename}".'
                )

    def backup_and_unmap(self, backup=False):
        """Backup and unmap memory dump."""

        if backup:
            self.backup()

        self.unmap()


def main():
    """Entry point"""

    parser = ArgumentParser(
        description="Unmap sections mapped in memory in the memory dump of a PE."
    )
    parser.add_argument(
        "-b", "--backup", action="store_true", help="back up memory dump"
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="show debug information"
    )
    parser.add_argument("-p", "--path", dest="dump", help="path to memory dump")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"{__program__} {__version__} by {__author__}",
    )

    args = parser.parse_args()

    if args.dump:
        dump = abspath(args.dump)
        unmapper = Unmapper(dump, debug=args.debug)
        if unmapper.is_unmapped():
            print(f'[!] File "{basename(dump)}" appears to be already unmapped.')
            sys.exit(1)
        else:
            unmapper.backup_and_unmap(args.backup)
    else:
        parser.print_usage()


if __name__ == "__main__":
    main()
