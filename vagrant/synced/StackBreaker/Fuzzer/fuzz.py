#!/usr/local/bin/python3

import monitor 

from pathlib import Path
import sys


program = Path(sys.argv[1])

monitor.program = program
monitor.monitor()

