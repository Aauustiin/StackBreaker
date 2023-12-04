import angr
import sys
print('imported')

program = sys.argv[1]

project = angr.Project(program, load_options={'auto_load_libs':False})
cfg = project.analyses.CFGFast()

for node in cfg.graph.nodes():
    print(f"Basic Block {node.addr}:")
    for successor in cfg.graph.successors(node):
        print(f"  -> {successor.addr}")