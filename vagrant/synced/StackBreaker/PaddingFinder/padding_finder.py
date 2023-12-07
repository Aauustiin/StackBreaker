import PaddingFinder.vulnerability_find as vuln
import PaddingFinder.padding_handler as pad

from pathlib import Path
from typing import List


def getPaddingLength(program:Path, verbose=False) -> List[int]:
    vuln.program = program
    pad.program = program

    funcs = vuln.getFunctions()
    funcs, addrs = vuln.findVulnerabilities(funcs)

    if verbose:
        print(f'Found {len(funcs)} potentially vulnerable functions:')
        for i in range(len(funcs)):
            print(f'{funcs[i]} @ {addrs[i]}')

    bPoints = []
    for f in funcs:
        bps = vuln.getBPoints(f)
        bPoints.append((f, bps))

    paddings = []
    for el in bPoints:
        if len(el[1]) == 0: continue

        if verbose: print(f'Function {el[0]}: ')

        for bp in el[1]:

            if verbose: print(f'    Trrying breakpoint {el[1]}...')

            padLength = pad.search(bp)
            if padLength > 0: 
                paddings.append(padLength)
                if verbose: print(f'    Found paddin of length {padLength}')
            elif verbose:
                print('    Could not find padding')

    return paddings


