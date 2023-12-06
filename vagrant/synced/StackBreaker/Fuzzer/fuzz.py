#!/usr/local/bin/python3

import score 

from pathlib import Path
import sys


program = Path(sys.argv[1])

score.program = program
score.score()

