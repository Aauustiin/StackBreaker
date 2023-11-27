#!/usr/bin/env python3

import argparse
from pathlib import Path

parser = argparse.ArgumentParser(
    description = "",
    formatter_class = argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("--command", default = "/bin/sh")
parser.add_argument("--envp", default = None)
parser.add_argument("--out-rop-path", default = None)

def main(args):
    argv = args.command.split()
    envp = args.envp.split()

    gadgets, data_address = parse_out_rop(Path(args.out_rop_path))

    push_array_of_strings(argv)
    push_array_of_strings(envp)
    

# Available gadgets
# .data stack base pointer
# .data stack pointer
# 

def parse_out_rop(path: Path):
    rop_gadgets = {
        ": mov dword ptr [edx], eax ; ret": None,
        ": pop edx ; ret": None,
        ": pop eax ; ret": None,
        ": xor eax, eax ; ret": None,
        ": inc eax ; ret": None,
        ": pop ebx ; ret": None,
        ": pop ecx ; pop ebx ; ret": None,
        ": int 0x80": None,
    }
    data_address = None
    with open(path) as out_rop:
        [line for line in out_rop if ]


def push_array_of_strings(array, stack_pointer) -> stack_pointer:
    pointers = []
    for string in array:
        pointers.append(stack_pointer)
        chunks = [string[i:i+4] for i in range(0, len(string), 4]
        chunks = [chunk.ljust(4, '\0') for chunk in chunks]
    for pointer in pointers:
        print(pointer)

if __name__ == "__main__":
    main(parser.parse_args())
