#!/usr/local/bin/python3

import binary_spy
import ga_search

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
    
    target = paths2Nodes[0]

    # print(vulnNodes)

    binary_spy.drawGraph()


    # print([hex(a) for a in target])
    # exeTrace = binary_spy.trace(binary_spy.mainAddr, '../Examples/good_input')
    # print([hex(a) for a in exeTrace])
    # exeTrace = binary_spy.trace(binary_spy.mainAddr, '../Examples/bad_input')
    # print([hex(a) for a in exeTrace])
    print(f'Found {len(paths2Nodes)} possible target(s)')

    for target in paths2Nodes:
        alphabet = string.ascii_letters + '\n'
        gen, best = ga_search.run_the_ga(target, pop_size=50, tournament_size=3, 
                                         genome_length=(5, 200), alphabet=alphabet)

        print(f'Found solution in {gen} generations:\n {best["solution"]}\n')




findFuzzing()

    

