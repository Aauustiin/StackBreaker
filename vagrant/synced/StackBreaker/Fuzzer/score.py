import sys
sys.path.append('..')
import PaddingFinder.vulnerability_find as vuln

import re
import angr
import capstone
from pathlib import Path
from cfgexplorer import cfg_explore
from angrutils import plot_cfg
import claripy
import logging

from typing import List

program: Path

def getVulnNodes(p: angr.Project, cfg) -> List:
    vuln.program = program
    funcs = vuln.getFunctions()
    vulnFuncs, vulnAdds = vuln.findVulnerabilities(funcs)
    vulnAdds = [int(addr, 0) for addr in vulnAdds]
    diff = p.entry -vuln.getEntryAddr()
    vulnAdds = [addr + diff for addr in vulnAdds]

    vulnNodes = []
    for f in cfg.kb.functions:
        node = cfg.get_any_node(f)
        if node.name in vulnFuncs:
            for b in cfg.functions[f].blocks:
                for addr in b.instruction_addrs:
                    if addr in vulnAdds:
                        vulnNodes.append(cfg.get_any_node(b.addr))
    ## ^good enough

    return vulnNodes

def getPath2Node(cfg, start, target) -> List[int]:
    vis = []
    queue = [[start]]
    nodePath = []
    while queue:
        path = queue.pop(0)
        node = path[-1]
        prev = start
        if len(path) >= 2:prev = path[-2]

        if node == target:
            nodePath = path
            break
        
        if node not in vis:
            vis.append(node)

            returnAddr = 0x0    
            if prev.block: returnAddr = prev.block.addr + prev.block.size
            succAddrs = node.successors
            succAddrs = [s.addr for s in succAddrs]
            if returnAddr in succAddrs:
                vis.remove(node)
                new_path = path.copy()
                returnNode = cfg.get_any_node(returnAddr)
                new_path.append(returnNode)
                queue.append(new_path)

            else:
                for succ in node.successors:
                    new_path = path.copy()
                    new_path.append(succ)
                    queue.append(new_path)

    addrPath = [n.addr for n in nodePath]
    return addrPath

def trace(p: angr.Project, startAddr) -> List[int]:
    logging.getLogger('angr').setLevel(logging.ERROR)

    startState = p.factory.blank_state(addr=startAddr)
    simgr = p.factory.simgr(startState)

    exeTrace = []
    while simgr.active:
        currentState = simgr.active[0]
        exeTrace.append(currentState.addr)

        simgr.step()

    return(exeTrace)

def calculateScore(refPath: list[int], exeTrace: list[int]) -> float:
    correctCount = 0
    for i in range(len(refPath)):
        if refPath[i] == exeTrace[i]:
            correctCount += 1

    return correctCount / len(refPath)
    

def score():
    proj = angr.Project(program, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    mainAddr = proj.loader.find_symbol('main').rebased_addr
    mainNode = cfg.get_any_node(mainAddr)

    vulnNodes = getVulnNodes(proj, cfg)
    paths2Nodes = []
    for node in vulnNodes:
        path = getPath2Node(cfg, mainNode ,node)
        paths2Nodes.append(path)

    print(paths2Nodes)

    exeTrace = trace(proj, mainAddr)
    print(exeTrace)

    score = calculateScore(paths2Nodes[0], exeTrace)
    print(score)



