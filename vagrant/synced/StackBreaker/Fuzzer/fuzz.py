#!/usr/local/bin/python3

import binary_spy
import ga_search
from binary_spy import vuln
from call_analysis import CallGraph

import sys
from pathlib import Path
import string

program = Path(sys.argv[1])

def findFuzzing():
    binary_spy.initialise(program)

    vulnNodes = binary_spy.getVulnNodes()
    paths2Nodes = []
    for node in vulnNodes:
        path = binary_spy.getPath2Node(node)
        paths2Nodes.append(path)

    print(f'Found {len(paths2Nodes)} possible target(s)')

    if len(paths2Nodes) == 0:
        print('Cold not find paths to the target(s)...')

    for target in paths2Nodes:
        alphabet = string.ascii_letters + '\n'
        gen, best = ga_search.run_the_ga(target, pop_size=50, tournament_size=3, 
                                         genome_length=(5, 200), alphabet=alphabet)

        print(f'Found solution in {gen} generations:\n {best["solution"]}\n')

def drawCFG(file:Path='cfg', complex=True):
    binary_spy.initialise(program)
    binary_spy.drawGraph(complex, file)

def printPath2Vuln():
    binary_spy.initialise(program)
    vulnNodes = binary_spy.getVulnNodes()

    print(f'Found {len(vulnNodes)} potential vulnerabilities:')

    for node in vulnNodes:
        print(f'    Node: {node.name}')
        binary_spy.getPath2Node(node, ouside_calls=True, pp=True)

def printCallPath():
    vuln.program = program
    cg = CallGraph(str(program), vuln.getFunctions())
    vulnFuncs, _ = vuln.findVulnerabilities(vuln.getFunctions())

    print(f'Found {len(vulnFuncs)} potentially vulnerable functions:')
    for f in vulnFuncs:
        print(f'{f}: ', end='')
        path = cg.getPath(f)
        for node in path:
            print(f'{node} ', end='')
            if node != f: print('-> ', end='')

        print()