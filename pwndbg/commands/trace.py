#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Stepping until an event occurs
"""
from __future__ import print_function
from __future__ import unicode_literals

import gdb
import pwndbg.commands
import pwndbg.trace


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def traceinst(*args):
    """Traces each instruction and prints it to stdout"""
    if pwndbg.trace.trace_inst(args):
        pwndbg.commands.context.context()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def tracecall(*args):
    """Traces each call and prints it to stdout"""
    if pwndbg.trace.trace_call(args):
        pwndbg.commands.context.context()
