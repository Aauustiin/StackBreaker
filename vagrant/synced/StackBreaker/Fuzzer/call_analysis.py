import subprocess as subp
import re

from typing import List, Tuple, Dict

class CallGraph:
    program: str
    level:  Dict[str, int]
    stack: List[str]
    succesors: Dict[str, List[str]]

    def __init__(self, program:str, funcs:List[str]):
        self.program = program

        funcs_dict = {f:0 for f in funcs}
        self.level = funcs_dict
        
        self.succesors = {}
        self.stack = []

        self.constructGraph(funcs)

    def updateLevel(self, i:str, j:str):
        if j in self.stack:
            self.succesors[i].remove(j)
            return
        
        if self.level[i] >= self.level[j]:
            self.stack.append(j)
            self.level[j] = self.level[i] + 1
            for s in self.succesors[j]:
                self.updateLevel(j, s)
            self.stack.pop()


    def findCalls(self, funct: str) -> List[str]:
        cmd = ['gdb', '--batch']
        cmd.extend(['--ex', 'disas ' + funct ])
        cmd.extend([self.program])

        gdbP = subp.run(cmd, stdout=subp.PIPE, stderr=subp.PIPE)
        gdbOut = gdbP.stdout.decode()

        callOpdPat = r'call\s+\w+\s+<(\w+)>' 
        callOpdPat = re.compile(callOpdPat)
        callOpds = callOpdPat.findall(gdbOut)
        callOpds = list(dict.fromkeys(callOpds))

        calledFuncs = []
        for opd in callOpds:
            if opd in self.level.keys():
                calledFuncs.append(opd)

        return calledFuncs

    def constructGraph(self, funcs:List[str]):
        level = {f:-1 for f in funcs}
        self.level= level

        edges :List[Tuple[str,str]] = []

        for f in funcs:
            called = self.findCalls(f)
            self.succesors[f] = called
            for c in called:
                edges.append((f, c))

        for f in funcs:
            if not ( f in [e[0] for e in edges] 
                    or f in [e[1] for e in edges]):
                del self.level[f]

        self.level['root'] = -1
        self.succesors['root'] = ['main']


        self.updateLevel('root', 'main')
        

        del self.level['root']
        del self.succesors['root']

    def printGraph(self):
        print(self.level)
        print(self.succesors)

    def getPath(self, target:str) -> List[str]:
        vis = []
        queue = [['main']]
        while queue:
            path = queue.pop(0)
            func = path[-1]

            if func == target:  
                return path

            if func not in vis:
                vis.append(func)
                for succ in self.succesors[func]:
                    new_path = path.copy()
                    new_path.append(succ)
                    queue.append(new_path)

        