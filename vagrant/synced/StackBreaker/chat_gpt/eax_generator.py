import random
import ctypes


def main():

    new_asm_instructions = '''
    add eax, 4            ; Adds 4 to EAX\n
    sub eax, 5            ; Subtracts 5 from EAX\n
    imul eax, 3           ; Multiplies EAX by 3. Result is in EAX. If the result is too large, EDX:EAX is used.\n
    inc eax               ; Increments EAX by 1\n
    dec eax               ; Decrements EAX by 1\n
    neg eax               ; Negates the value in EAX (two's complement negation)\n
    and eax, 0xFF         ; Performs bitwise AND on EAX with 0xFF\n
    or eax, 0xFF          ; Performs bitwise OR on EAX with 0xFF\n
    xor eax, 0xFF         ; Performs bitwise XOR on EAX with 0xFF\n
    not eax               ; Performs bitwise NOT on EAX\n
    '''
    # Initialize EAX to 0
    eax = 0

    # Splitting the instructions into a list, stripping leading spaces, and filtering out empty/comment lines
    instruction_list = [line.strip() for line in new_asm_instructions.strip().split('\n') if line.strip() and not line.strip().startswith(';')]

    # Selecting a random subset of instructions
    num_of_instructions_to_select = 5
    # selected_instructions = random.sample(instruction_list, num_of_instructions_to_select)
    selected_instructions = [random.choice(instruction_list) for _ in range(num_of_instructions_to_select)]
    selected_instructions.append('and eax, 0xFFFFFFFF')
    for instruction in selected_instructions:
        print(instruction)
        eax = simulate_instruction(eax, instruction)

    print(f"Final value of EAX: {eax}")


    # Joining the selected instructions back into a string
    selected_instructions_str = '\n'.join(selected_instructions)

    # Passing the selected instructions to the insert_instructions function
    insert_instructions('eax.s', 'mov eax, 0', 'mov ebx, .data', selected_instructions_str)

def insert_instructions(file_name, start_text, end_text, new_instructions):
    with open(file_name, 'r') as file:
        lines = file.readlines()

    start_index = next((i for i, line in enumerate(lines) if start_text in line), None)
    end_index = next((i for i, line in enumerate(lines) if end_text in line), None)

    if start_index is not None and end_index is not None and start_index < end_index:
        indentation = ''.join(char for char in lines[start_index] if char.isspace())
        indented_instructions = [indentation + line + '\n' for line in new_instructions.strip().split('\n')]

        # Replace existing content between start_index and end_index with the new instructions
        lines[start_index + 1:end_index] = indented_instructions
    else:
        print("Couldn't find the specified start and end text in the file.")

    with open(file_name, 'w') as file:
        file.writelines(lines)

def simulate_instruction(eax, instruction):
    parts = instruction.split(';')[0].split()  # Splitting at ';' to remove the comment
    operation = parts[0]
    operand = int(parts[2], 0) if len(parts) > 2 else None

    print(f"EAX before '{operation}': {eax}")

    if operation == 'add':
        eax += operand
    elif operation == 'sub':
        eax -= operand
    elif operation == 'imul':
        eax *= operand
    elif operation == 'inc':
        eax += 1
    elif operation == 'dec':
        eax -= 1
    elif operation == 'neg':
        eax = -eax
    elif operation == 'and':
        eax &= operand
    elif operation == 'or':
        eax |= operand
    elif operation == 'xor':
        eax ^= operand
    elif operation == 'not':
        eax = ~eax

    print(f"EAX after '{operation}': {eax}")
    unsigned_eax = format(eax, '02x')
    print(f"Unsigned '{operation}': {unsigned_eax}")

    return eax


main()