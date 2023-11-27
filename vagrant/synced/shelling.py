file_name = 'hello.s'

try:
    with open(file_name, 'r') as file:
        for line in file:
            line = line.strip()
            # Check if the line contains potential gadget-ending instructions
            if any(instruction in line for instruction in ['ret', 'pop', 'jmp']):
                print(f"Potential gadget found: {line}")
            else:
                print(line)  # Print other lines normally

except FileNotFoundError:
    print(f"The file {file_name} was not found.")
except Exception as e:
    print(f"An error occurred: {e}")
