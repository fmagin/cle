# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed November 2019 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).


from struct import calcsize,unpack
from io import BytesIO

INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000

import logging

l = logging.getLogger(__name__)
print(__name__)



class IndirectSymbolTableParser(object):

    def __init__(self):
        pass

    def analyze(self,binary):

        blob = IndirectSymbolTableParser._get_indirect_symbol_table_blob(binary)
        return IndirectSymbolTableParser._parse_isymtab(blob,binary)

    @staticmethod
    def _parse_isymtab(blob, binary):
        isymnum = len(blob) // 4

        fmt = ("<" if binary.arch.memory_endness == "Iend_LE" else ">") + "I"

        str_blob = BytesIO(blob)
        result = []
        for i in range(0,isymnum):
            symtab_offset = unpack(fmt,str_blob.read(4))[0]
            l.debug("symtab_offset={0}".format(symtab_offset))
            result.append(symtab_offset)
        return result

    @staticmethod
    def _get_indirect_symbol_table_blob(binary):
        """Extracts the indirect symbol table blobs"""
        ncmds = binary.ncmds
        sizeofcmds = binary.sizeofcmds
        lc_offset = (7 if binary.arch.bits == 32 else 8) * 4

        count = 0
        offset = lc_offset
        # NOTE: All offsets are FILE offsets
        fp = binary.binary_stream
        blob = None
        while count < ncmds and (offset - lc_offset) < sizeofcmds:
            l.debug("Parsing offset 0x{0:X}".format(offset))
            count += 1
            cmd, size = binary._unpack("II", fp, offset, 8)

            if cmd in [0xb]:  # LC_DYSYMTAB
                l.debug("found LC_DYSYMTAB @ 0x{0:X}".format(offset))
                tmp = binary._unpack("16I", fp, offset, calcsize("16I"))
                isymoff = tmp[14]
                isymnum = tmp[15]

                l.debug("isymoff=0x{0:X} isymnum=0x{1:X}".format(isymoff, isymnum))

                # assertion
                if blob is not None:
                    raise ValueError("Multiple DySymTabs!")

                fp.seek(isymoff)
                blob=fp.read(4*isymnum)
            offset += size
        return blob

class StubParser:
    """
    Resolves stubs by inspecting the indirect symbol table
    """

    def __init__(self):
        pass

    @staticmethod
    def analyze(binary: 'MachO'):
        ip = IndirectSymbolTableParser()
        indirect_symbol_table = ip.analyze(binary)

        # find all sections that contain stubs
        l.info("Processing stubs in %d segments", len(binary.segments))
        for seg in binary.segments:
            if seg.is_executable:  # optimization: Non-exec segments cannot contain stubs (at least it makes no sense)
                for sec in seg.sections:
                    if sec.type == 0x8:  # stubs

                        indirect_sym_base = sec.reserved1  # offset into the indirect symbol table
                        stub_size = sec.reserved2  # size of the stubs
                        sec_size = sec.memsize
                        sec_base = sec.vaddr
                        l.debug("Found stubs in sec %s.%s, isym_base: %x, stub_size: %x, sec_size: %x, sec_base: %x",
                                sec.segname, sec.sectname, indirect_sym_base, stub_size, sec_size, sec_base)

                        # go through all the stubs and annotate the corresponding symbols
                        for offset in range(0, sec_size, stub_size):

                            addr = sec_base + offset
                            indirect_sym_index = indirect_sym_base + offset // stub_size
                            l.debug("Handling stub @ %x (%x+%x), index %d", addr, sec_base, offset, indirect_sym_index)
                            sym_index = indirect_symbol_table[indirect_sym_index]
                            l.debug("addr=0x{0:X} indirect_sym_index={1} sym_index=0x{2:X}" \
                                    .format(addr, indirect_sym_index, sym_index))

                            if sym_index not in [0xC0000000, 0x40000000, 0x80000000]:
                                symbol = binary.get_symbol_by_insertion_order(sym_index)
                                symbol.symbol_stubs.append(addr)
                                l.debug("Adding 0x{:08x} as a stub for '{}'".format(addr, symbol.name))
                            else:
                                l.debug("Indirect symbol removed by strip - skipping ")
                                # TODO: Find out how to handle this case during symex


import typing
if typing.TYPE_CHECKING:
    from cle import MachO