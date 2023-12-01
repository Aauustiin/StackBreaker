import subprocess as subp
import math
import re
import os
from enum import Enum
from pathlib import Path

program: Path

def createPadding(len, file='padding', pad=b'A'):
    padding = len * pad

    padf = open(file, 'wb')
    padf.write(padding)
    padf.close()

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

def search(breakPoint, pad='A'):
    padBytes = pad.encode()
    padStr = hex(ord(pad))[2:]
    padF = 'padding'

    lowLim = 0
    uppLim = 1024


    guess =  math.floor( (lowLim + uppLim) / 2 )
    while True:
        createPadding(guess, padF, pad=padBytes)

        # print('    > Trying padding length {}...'.format(guess))

        found, searchScope = checkPad(breakPoint, padF, padStr)

        if found: break

        if searchScope == Scope.LOW:
            lowLim = guess
            # print('    > Not enough padding')

        if searchScope == Scope.HIGH:
            uppLim = guess
            # print('    > Too much padding')

        guess = math.floor( (lowLim + uppLim) / 2 )

        if searchScope == Scope.CLOSE:
            # print('    > Almost there...')
            while True:
                guess -= 1
                createPadding(guess, file=padF ,pad=padBytes)
                found , _ = checkPad(breakPoint, padF, padStr)
                if found: break

        if uppLim - guess <= 1:
            guess = -1
            break

        os.remove(padF)

    return guess


