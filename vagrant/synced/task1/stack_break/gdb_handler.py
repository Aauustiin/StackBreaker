import subprocess as subp
import re
from enum import Enum

program = ''

def getFunctions_g():

    cmd = ['gdb', '--batch']
    cmd.extend(['--ex', 'info functions'])
    cmd.extend([program])

    gdbProcess = subp.run(cmd, stdout=subp.PIPE)
    gdbOut = gdbProcess.stdout.decode()

    funcPat = r'^\b(\w+)\s+' # return type
    funcPat += r'(\w+)\s*' # function name
    funcPat += r'\((.*?)\)\s*;' # arguments
    funcPat = re.compile(funcPat, re.MULTILINE)
    matches = funcPat.findall(gdbOut)

    functions = []
    for match in matches:
        if match[0] == 'void': continue
        arguments = match[2].replace(' ','').split(', ')
        for arg in arguments:
            if arg == 'char*':
                functions.append(match[1])

    return functions

def getFunctions_static():
    cmd = ['objdump', '-d']
    cmd.append(program)

    dumpProcess = subp.run(cmd, stdout=subp.PIPE)
    dumpOut = dumpProcess.stdout.decode()

    funcPat = r'[0-9A-Fa-f]{8}\s+<(\w.+?)>:' # function name
    funcPat += r'(.*?)\n\n' # function body
    funcPat = re.compile(funcPat, re.DOTALL)
    funcs = funcPat.findall(dumpOut)

    vulnFuncs = []
    for f in funcs:
        name = f[0]
        body = f[1]
        
        strcpyPat = r'call\s+80481d0\s'
        strcpyPat = re.compile(strcpyPat, re.MULTILINE)
        match = strcpyPat.search(body)
        if match:
            vulnFuncs.append(name)

    return vulnFuncs

def getFunctions(compile_flags:[str]=['static','g']):
    functions = []

    if 'g' in compile_flags:
        functions = getFunctions_g()

    elif 'static' in compile_flags:
        functions = getFunctions_static()

    return functions

def getBPoints(func):

    cmd = ['gdb', '--batch']
    cmd.extend(['--ex', 'disassemble ' + func])
    cmd.extend([program])

    gdbProcess = subp.run(cmd, stdout=subp.PIPE)
    gdbOut = gdbProcess.stdout.decode()
    
    retAddPat = r'\s*(0x\w{8}).*' # address of instruction
    retAddPat += r'(?=\n.*ret)' # before ret
    retAddPat = re.compile(retAddPat, re.MULTILINE)
    bPoints = retAddPat.findall(gdbOut)

    return bPoints

class Scope(Enum):
    LOW = 0
    HIGH = 1
    CLOSE = 2
 
def checkPad(bPoint, padf, pad):

    cmd = ['gdb', '--batch']
    cmd.extend(['--ex', 'b *' + bPoint])
    cmd.extend(['--ex', 'run ' + padf])
    cmd.extend(['--ex', 'x/4wx $ebp'])
    cmd.extend(['--ex', 'c'])
    cmd.extend([program])

    gdbProcess = subp.run(cmd, stdout=subp.PIPE, stderr=subp.PIPE)
    gdbOut = gdbProcess.stdout.decode()

    OWAddsPat = r'\t(0x(?:[0-9A-Fa-f][0-9A-Fa-f])+'
    OWAddsPat += r'(?:' + pad + r'+))'
    OWAddsPat = re.compile(OWAddsPat, re.MULTILINE)
    matches = OWAddsPat.findall(gdbOut)
    OWAdds = len(matches)
    OWAddsStr = ' '.join(matches)

    fullyOWAddsPat = r'\s?(0x(?:' + pad + r'){4})'
    fullyOWAddsPat = re.compile(fullyOWAddsPat)
    matches = fullyOWAddsPat.findall(OWAddsStr)
    fullyOWAdds = len(matches)

    partOWAdds = OWAdds - fullyOWAdds

    if fullyOWAdds == 1 and partOWAdds == 0:
        return True, Scope.CLOSE
    
    if fullyOWAdds == 0:
        return False, Scope.LOW
    
    if fullyOWAdds == 4:
        return False, Scope.HIGH
    
    return False, Scope.CLOSE