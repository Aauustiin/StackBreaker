import sys
sys.path.append('..')
import PaddingFinder.vulnerability_find as vuln

import re
import angr
import capstone
from pathlib import Path
from cfgexplorer import cfg_explore
from angrutils import plot_cfg

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

def getPath2Node(cfg, start, target):
    vis = []
    queue = [[start]]
    while queue:
        path = queue.pop(0)
        node = path[-1]

        if node == target:
            return path
        
        if node not in vis:
            vis.append(node)
            for succ in node.successors:
                new_path = path.copy()
                new_path.append(succ)
                queue.append(new_path)

def monitor():
    proj = angr.Project(program, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    get_pc_thunk_addr = proj.loader.find_symbol('__x86.get_pc_thunk.bx').rebased_addr
    get_pc_thunk_node = cfg.get_any_node(get_pc_thunk_addr)

    mod_cfg = cfg.copy()
    for edge in cfg.graph.edges:
        if get_pc_thunk_node == edge[1]:
            print(edge)
            mod_cfg.remove_edge(edge[0], edge[1])

    plot_cfg(cfg, 'out')

    mainAddr = proj.loader.find_symbol('main').rebased_addr
    mainNode = mod_cfg.get_any_node(mainAddr)

    vulnNodes = getVulnNodes(proj, mod_cfg)
    for node in vulnNodes:
        node.block.pp()
        path = getPath2Node(mod_cfg, mainNode ,node)
        print('\n Path to the node:')
        for node in path:
            print(f'succs: {node.successors}')
            if node.block:
                node.block.pp()
            else:
                print(f'Block at addr {hex(node.addr)} not found')
            print('>                 >')
