#!/usr/bin/python3

import padding_finder as pad

import argparse
from pathlib import Path
import sys

parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("--command", default="/bin/sh")
parser.add_argument("--envp", default="")
parser.add_argument("--out-rop-path", default=Path("examples/Vuln3/Vuln3-32/out-rop.txt"))
parser.add_argument("-p", "--program", default=Path("examples/Vuln3/Vuln3-32/vuln3-32"))

def main():
    print("Hello, world!")
    paddings = pad.getPaddingLength(parser.parse_args().program)
    print(paddings)


if __name__ == "__main__":
    main()
