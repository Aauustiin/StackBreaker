#!/usr/bin/python3
import subprocess

cmd = ['gdb','--quiet','-x','gdbscript','../vuln3-32']
gdb = subprocess.run(cmd, stdout=subprocess.PIPE)
print(gdb.stdout.decode())

