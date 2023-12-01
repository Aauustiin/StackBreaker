#!/usr/bin/python3

import vulnerability_find as vuln
import padding_handler as pad
# from call_analysis import CallGraph

import sys

if not len(sys.argv) == 2:
    print("[*] Improper usage.")
    print("[*] Correct program format: exploit_stack PROGRAM_PATH")
    exit(0)

program = sys.argv[1]

vuln.program = program
pad.program = program

funcs = vuln.getFunctions()
fNames = [f[0] for f in funcs]
# g = CallGraph(program, fNames)
# g.printGraph()
# for f in fNames:
#     print(g.getPath())
funcs = vuln.getVulerableFunctions(funcs)

# sys.exit()

bPoints = []
for f in funcs:
    bps = vuln.getBPoints(f)
    bPoints.append((f, bps))

print(bPoints)

paddings = []
for el in bPoints:
    if len(el[1]) == 0: continue
    print('Function {}:'.format(el[0]))
    for bp in el[1]:
        print('  > Trying break point {}...'.format(bp))
        padLength = pad.search(bp)
        if padLength > 0: 
            paddings.append(padLength)

print('Found {} possible paddings'.format(len(paddings)))





