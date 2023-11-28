#!/usr/bin/env python3

import re
import argparse
from pathlib import Path


parser = argparse.ArgumentParser(
    description = "",
    formatter_class = argparse.ArgumentDefaultsHelpFormatter,
)
# parser.add_argument("--command", default = "/bin/sh")
# parser.add_argument("--envp", default = None)
parser.add_argument("--shellcode", default= None)
parser.add_argument("--out-rop-path", default = None)

def main(args):
    # argv = args.command.split()
    #envp = args.envp.split()s
    # push_array_of_strings(argv)
    contents = reads(args.shellcode)
    print(contents)
    gadgets, data_address = parse_out_rop(Path(args.out_rop_path))

def reads(file_name):
    rodata_start = False
    rodata_contents = []
    try:
        with open(file_name, 'r') as file:
            for line in file:
                line = line.strip()
                if '.rodata' in line:
                    rodata_start = True
                    continue

                if rodata_start: 
                    if any(data_directive in line for data_directive in ['db', 'dw', 'dd', 'dq', 'dt']):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1: 
                            rodata_contents.append(parts[1])

    except FileNotFoundError:
        print(f"The file {file_name} was not found.")
    except Exception as e:
         print(f"An error occurred: {e}")

    return rodata_contents


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
                    print(data_address)

            elif any(gadget in line for gadget in rop_gadgets.keys()):
                tokens = line.split()
                gadget_key = ' '.join(tokens[1:])
                rop_gadgets[gadget_key] = tokens[0]

    return rop_gadgets, data_address

# def push_array_of_strings(array, rop_gadgets):
#     for string in array:
#         chunks = [string[i:i+4] for i in range(0, len(string), 4)]
#         chunks = [chunk.ljust(4, '\0') for chunk in chunks]

#         for chunk in chunks:
#             print(chunk)

if __name__ == "__main__":
    main(parser.parse_args())