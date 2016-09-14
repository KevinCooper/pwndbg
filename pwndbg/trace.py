#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Commands for setting following and recording
flow of execution.
"""
from __future__ import print_function
from __future__ import unicode_literals

import capstone

import gdb
import pwndbg.disasm
import pwndbg.regs
import pwndbg.commands
import pwndbg.commands.nearpc
import pwndbg.symbol
import pwndbg.color.disasm as D
import re
jumps = set((
    capstone.CS_GRP_CALL,
    capstone.CS_GRP_JUMP,
    capstone.CS_GRP_RET,
    capstone.CS_GRP_IRET
))

interrupts = set((capstone.CS_GRP_INT,))

def trace_inst(args = None):
    """
    If an instruction semantic matches one of the input regexs,
    then the instruction is printed to stdout.

    If no input, all instructions are printed
    """

    """ Default match everything """
    if args is None or not args:
        args = [".*"]

    ins = pwndbg.disasm.one(pwndbg.regs.pc)
    if not ins:
        return None

    while ins:
        address = '%#x' % ins.address
        symbol = pwndbg.symbol.get(ins.address)
        asm = D.instruction(ins)
        if( any(re.match(regex, asm) for regex in args) ):
            print(address, symbol, asm)
        ins = pwndbg.disasm.one(ins.next)

    return False

def trace_call(args = None):
    if args is None or not args:
        args = [".*call.*"]
    return trace_inst(args)
