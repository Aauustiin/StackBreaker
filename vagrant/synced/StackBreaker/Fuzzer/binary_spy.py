import sys
sys.path.append('..')
import PaddingFinder.vulnerability_find as vuln

import os
import angr
from pathlib import Path
from cfgexplorer import cfg_explore
from angrutils import plot_cfg
import logging
import subprocess as subp
import re

from typing import List

prog: Path
proj: angr.Project
cfg: angr.analyses.cfg.CFGFast
mainAddr: int

def getVulnNodes() -> List:
    vuln.program = prog
    funcs = vuln.getFunctions()
    vulnFuncs, vulnAdds = vuln.findVulnerabilities(funcs)
    vulnAdds = [int(addr, 0) for addr in vulnAdds]
    diff = proj.entry -vuln.getEntryAddr()
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

def getPath2Node(target, ouside_calls=False, pp=False) -> List[int]:
    mainNode = cfg.get_any_node(mainAddr)

    vis = []
    queue = [[mainNode]]
    nodePath = []
    while queue:
        path = queue.pop(0)
        node = path[-1]
        prev = mainNode
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

    if not ouside_calls:
        for addr, node in zip(addrPath, nodePath):
            block = cfg.get_any_node(addr).block
            if block == None:
                addrPath.remove(addr)
                nodePath.remove(node)

    if pp:
        for node in nodePath:
            blk = node.block
            if blk:
                blk.pp()
            else:
                print(f'Block not in scope @ {hex(node.addr)}')

            print('    >        >')


    return addrPath

def trace(startAddr: int, file: Path=None) -> List[int]:
    diff = vuln.getEntryAddr(run=True) - proj.entry

    gdbscript = 'run\nbreak *' + hex(startAddr + diff) + '\nrun '
    if file: gdbscript += str(file) + '\n'
    gdbscript += 'while 1\n  stepi\nend\nquit'

    f = open('gdbscript', 'w')
    f.write(gdbscript)
    f.close()

    cmd = ['gdb', '--batch']
    cmd.extend(['-x', 'gdbscript'])
    cmd.extend([prog])

    gdbProcess = subp.run(cmd, stdout=subp.PIPE, stderr=subp.PIPE)
    gdbOut = gdbProcess.stdout.decode()

    addrPat = r'(^0x[0-9A-Fa-f]{8})'
    addrPat = re.compile(addrPat, re.MULTILINE)

    addrs = addrPat.findall(gdbOut)
    addrs = [int(addr, 0) - diff for addr in addrs]

    exeTrace = [startAddr]
    while addrs:
        addr = addrs.pop(0)
        node = cfg.get_any_node(addr)
        if node: exeTrace.append(addr)

    return exeTrace

def calculateScore(refPath: list[int], exeTrace: list[int]) -> float:

    correctCount = 0
    for node in refPath:
        if node in exeTrace:
            correctCount += 1

    return correctCount / len(refPath)

def initialise(program: Path):
    global prog
    prog = program

    global proj
    proj = angr.Project(prog, auto_load_libs=False)

    global cfg
    cfg = proj.analyses.CFGFast()

    global mainAddr
    mainAddr = proj.loader.find_symbol('main').rebased_addr

    logging.getLogger('angr').setLevel(logging.ERROR)

def drawGraph(complex=True, file='cfg'):
    if complex:
        plot_cfg(cfg, file)
    else:
        file += '.png'
        cfg_explore(prog, output=file)

def score(solution: bytes, target: list[int]) -> float:
    inputFile = open('fuzz', 'wb')
    inputFile.write(solution)
    inputFile.close

    inputFile = Path('fuzz')

    exeTrace = trace(mainAddr, inputFile)

    os.remove(inputFile)

    return calculateScore(target, exeTrace)