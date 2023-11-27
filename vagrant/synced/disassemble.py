from capstone import *

def disassemble(file_path):
    try:
        # Read the binary data from the file
        with open(file_path, 'rb') as f:
            machine_code = f.read()
    except IOError as e:
        print(f"Error opening file: {e}")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    # Create a Capstone disassembler
    # Assuming the machine code is for x86 architecture and in 64-bit mode
    # Change the architecture and mode as per your requirements
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Disassemble the machine code
    for i in md.disasm(machine_code, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

# Example usage
disassemble("hello.s")
