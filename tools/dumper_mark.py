#!/usr/bin/env python2.7

from __future__ import print_function
import os
import sys
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="verbose output", action="store_true")
parser.add_argument("-s", "--snapshot", help="prefix the current file with 'shapshot.'", action="store_true")
args = parser.parse_args()

if args.snapshot:
    signame = 'USR2'
else:
    signame = 'USR1'
    
    
if args.verbose:
    print('Sending SIG{} to the trace_dumper process'.format(signame))
    
program = 'killall'
argv    = (program, '-' + signame, 'trace_dumper')

os.execvp(program, argv)
print('Failed to run the command: ' + ' '.join(argv), file=sys.stderr,)


    