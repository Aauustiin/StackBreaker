import gdb_handler as gdb
from gdb_handler import Scope
import math
import os

def createPadding(len, file='padding', pad=b'A'):
    padding = len * pad

    padf = open(file, 'wb')
    padf.write(padding)
    padf.close()

def search(breakPoint, pad='A'):
    padBytes = pad.encode()
    padStr = hex(ord(pad))[2:]

    lowLim = 0
    uppLim = 1024

    guess =  math.floor( (lowLim + uppLim) / 2 )
    while True:
        createPadding(guess, pad=padBytes)

        print('    > Trying padding length {}...'.format(guess))

        found, searchScope = gdb.checkPad(breakPoint, 'padding', padStr)

        if found: break

        if searchScope == Scope.LOW:
            lowLim = guess
            print('    > Not enough padding')

        if searchScope == Scope.HIGH:
            uppLim = guess
            print('    > Too much padding')

        guess = math.floor( (lowLim + uppLim) / 2 )

        if searchScope == Scope.CLOSE:
            print('    > Almost there...')
            while True:
                guess -= 1
                createPadding(guess, pad=padBytes)
                found , _ = gdb.checkPad(breakPoint, 'padding', padStr)
                if found: break

        if uppLim - guess <= 1:
            guess = -1
            break

    if guess == -1:
        print('    > Could not find padding. Giving up...')
    else:
        print('    > Found padding!')
        print('    > Padding length: {}'.format(guess))

    return guess



