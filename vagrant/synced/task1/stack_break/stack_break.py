#!/usr/bin/python3

import gdb_handler as gdb
import padding_handler as pad

# if not len(sys.argv) == 2:
#     print("[*] Improper usage.")
#     print("[*] Correct program format: exploit_stack PROGRAM_PATH")

# program = sys.argv[1]
program = '../vuln3-32'

gdb.program = program

funcs = gdb.getFunctions()

bPoints = []
for f in funcs:
    bps = gdb.getBPoints(f)
    bPoints.append((f, bps))

print(bPoints)

for el in bPoints:
    print('Function {}:'.format(el[0]))
    for bp in el[1]:
        print('  > Trying break point {}...'.format(bp))
        padLength = pad.search(bp)
        print('  > Padding length: {}'.format(padLength))





