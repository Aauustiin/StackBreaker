# Python code to read a .s (shellcode) file line by line

# Replace 'example.s' with the path to your file
file_name = 'hello.s'

try:
    with open(file_name, 'r') as file:
        # Reading each line in the file
        for line in file:
            print(line.strip())  # Print each line without trailing newline character
except FileNotFoundError:
    print(f"The file {file_name} was not found.")
except Exception as e:
    print(f"An error occurred: {e}")
