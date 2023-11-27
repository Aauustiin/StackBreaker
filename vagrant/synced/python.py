from capstone import *

file_name = 'hello.s'

try:
    with open(file_name, 'r') as file:
        shellcode = b""
        for line in file:
            line = line.strip()
            try:
                # Convert each line from hex to bytes
                bytes_line = bytes.fromhex(line)
                shellcode += bytes_line
            except ValueError as ve:
                print(f"Skipping non-hexadecimal content: {line} - Error: {ve}")

    # Initialize the disassembler (assuming x86 architecture here)
    md = Cs(CS_ARCH_X86, CS_MODE_32)  # Change to CS_MODE_64 for x64 architecture

    # Disassemble and find gadgets
    for instruction in md.disasm(shellcode, 0x1000):
        print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")

        # Example: Finding gadgets that end with 'ret'
        if instruction.mnemonic == 'ret':
            # Process the gadget here
            pass  # Implement your logic

except FileNotFoundError:
    print(f"The file {file_name} was not found.")
except Exception as e:
    print(f"An error occurred: {e}")
