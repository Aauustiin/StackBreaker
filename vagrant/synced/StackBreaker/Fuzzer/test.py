#!/usr/local/bin/python3

import angr
import monkeyhex
from angrutils import *
import sys
import logging
from cfgexplorer import cfg_explore

prog_path = sys.argv[1]

proj = angr.Project(prog_path, auto_load_libs=False)

cfg = proj.analyses.CFGFast()
entry_node = cfg.model.get_any_node(proj.entry)

print(f'{len(cfg.model.get_all_nodes(proj.entry))} context for entry block')

print(f'pred: {entry_node.predecessors}')
print(f'succ: {entry_node.successors}')

plot_cfg(cfg, 'cfg_util')
cfg_explore(binary=prog_path, output="cfg_img.jpg")