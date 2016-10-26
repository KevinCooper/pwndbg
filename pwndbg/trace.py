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
import pwndbg.vmmap
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

    p = re.compile("\s*[^ ]*\s*([^,]*),\s*([^<]*)([<].*[>])*")
    while ins:
        address = '%#x' % ins.address
        symbol = pwndbg.symbol.get(ins.address)
        asm = D.instruction(ins)

        if( any(re.match(regex, asm) for regex in args) ):
            print(address, symbol, asm)

            m = p.search(asm)

            if(m):
                for op in m.groups():
                    if(op is None) :  continue
                    elif(op.startswith("0")): continue
                    elif(op.startswith("-")): continue
                    elif(op.startswith("[")): continue
                    elif(pwndbg.regs[op.strip()] != None):
                        temp = pwndbg.regs[op.strip()]
                        print('%03s: %s'%(op, hex(temp)))
                    elif(op.startswith("<")):
                        temp = pwndbg.memory.u(op.strip()[1:-1])
                        print('%s: %s'%(op, hex(temp)))

        ins_next = pwndbg.disasm.one(ins.next)
        gdb.execute('nexti', from_tty=False, to_string=True)
        ins = pwndbg.disasm.one(pwndbg.regs.pc)

    return False

def trace_call(args = None):
    if args is None or not args:
        args = [".*call.*"]
    return trace_inst(args)
