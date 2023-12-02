import PaddingFinder.vulnerability_find as vuln
import PaddingFinder.padding_handler as pad

from pathlib import Path
from typing import List


def getPaddingLength(program:Path) -> List[int]:
    vuln.program = program
    pad.program = program

    funcs = vuln.getFunctions()
    funcs = vuln.getVulerableFunctions(funcs)
    bPoints = []
    for f in funcs:
        bps = vuln.getBPoints(f)
        bPoints.append((f, bps))

    paddings = []
    for el in bPoints:
        if len(el[1]) == 0: continue
        for bp in el[1]:
            padLength = pad.search(bp)
            if padLength > 0: 
                paddings.append(padLength)

    return paddings
