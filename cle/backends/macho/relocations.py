# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed November 2019 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cle.backends.macho.symbol import AbstractMachOSymbol
    from .macho import MachO

from ..relocation import Relocation

import logging

l = logging.getLogger(__name__)

class GenericMachORelocation(Relocation):
    """Some relocation-like class to somewhat implement dynamic loading
    DO NOT TRUST THAT THIS IS SANE OR HAS ANYTHING TO DO WITH WHAT ACTUALLY HAPPENS
    I have no idea if the concept of relocations as expected and implemented in the Relocation system is how *OS works.
    Rebasing is definitely broken
    But at least it allows the SimProcedures to be resolved when passing some special flags to the loader
    """

    def __init__(self, owner: 'MachO', symbol: 'AbstractMachOSymbol', relative_addr: int):
        l.debug("MachO Relocation for symbol %s created" % symbol)
        super(GenericMachORelocation, self).__init__(owner, symbol, relative_addr)
        if hasattr(symbol, 'library_name'):
            lib = os.path.basename(symbol.library_name)
            self.resolvewith = lib.decode()

    def resolve_symbol(self, solist, bypass_compatibility=False, thumb=False): # pylint: disable=unused-argument
        if self.resolved:
            return True
        new_symbol = self.owner.loader.extern_object.make_extern(self.symbol.name, sym_type=self.symbol._type, thumb=thumb)
        l.debug("Created external symbol %s for relocation %s" % (new_symbol, self ))
        self.resolve(new_symbol)
        return True

    @property
    def value(self):
        # Not sure if that is how this should work?
        return self.resolvedby.rebased_addr