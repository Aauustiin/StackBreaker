from pathlib import Path
from io import StringIO
import sys

def extract_functions(out_rop_path):
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

    with open(out_rop_path, 'r') as file:
        execve_buffer = StringIO()
        null_buffer = StringIO()
        started = False
        finished = False

        for line in file:

            line = line.lstrip()

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

    if data_address == 0:
        print('Error: ROPgadget exploit generation unsuccesful')
        sys.exit(1)

    push_bytes_function.seek(0)
    push_ptr_function = StringIO()
    flag = False
    for line in push_bytes_function.readlines():
        if "def push_bytes(data, address):" in line:
            push_ptr_function.write("def push_ptr(ptr, address):\n")
        elif "p += data" in line:
            flag = True
        elif flag:
            tokens = line.split()
            tokens[3] = "ptr)"
            new_line = ' '.join(tokens) + '\n'
            push_ptr_function.write("    " + new_line)
            push_ptr_function.write(line)
        else:
            push_ptr_function.write(line)

    push_null_function.write(null_buffer.getvalue())
    push_null_function.write("    return p\n")
    execve_syscall_function.write(execve_buffer.getvalue())
    execve_syscall_function.write("    return p\n")
    push_bytes_function.write("    return p\n")
    push_ptr_function.write("    return p\n")

    push_ptr_function = push_ptr_function.getvalue()
    push_bytes_function = push_bytes_function.getvalue()
    push_null_function = push_null_function.getvalue()
    execve_syscall_function = execve_syscall_function.getvalue()

    execve_syscall_function = execve_syscall_function.replace("address", "argv_ptr", 1)
    execve_syscall_function = execve_syscall_function.replace("address", "envp_ptr", 1)

    extracted_functions_path = Path("Extracted_Functions.py")
    with open(extracted_functions_path, 'w') as file:
        file.write("from struct import pack\n\n\n")
        file.write(push_bytes_function)
        file.write("\n\n")
        file.write(push_ptr_function)
        file.write("\n\n")
        file.write(push_null_function)
        file.write("\n\n")
        file.write(execve_syscall_function)

    return data_address, extracted_functions_path
