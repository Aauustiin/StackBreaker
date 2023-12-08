from io import StringIO
from collections import Counter
import string
from itertools import chain


def keyword_trim(in_gadgets: str, keywords) -> str:
    out_gadgets = StringIO()
    in_lines = in_gadgets.splitlines()
    punctuation_remover = str.maketrans('', '', string.punctuation)
    for line in in_lines:
        clean_line = line.translate(punctuation_remover)
        tokens = clean_line.split()
        if any([keyword in tokens for keyword in keywords]):
            out_gadgets.write(line + '\n')
    return out_gadgets.getvalue()


def rare_token_trim(in_gadgets: str, whitelist, required_tokens: int) -> str:
    operands = []
    opcodes = []
    assembly_lines = []
    punctuation_remover = str.maketrans('', '', string.punctuation)
    in_lines = in_gadgets.splitlines()
    for line in in_lines:
        tokens = line.split()
        assembly = ' '.join(tokens[1:])  # Skip the hex value at the start
        assembly = assembly.split(';')  # Split into assembly instructions
        assembly = [instruction.translate(punctuation_remover) for instruction in assembly]
        assembly = [instruction.split() for instruction in assembly]
        assembly_lines += [list(chain(*assembly))]
        operands += [instruction[0] for instruction in assembly]
        opcodes += [instruction[1:] for instruction in assembly if len(instruction) <= 3]
    opcodes = list(chain(*opcodes))
    opcodes = [item for item in opcodes if item not in whitelist]
    operands = [item for item in operands if item not in whitelist]
    tokens = operands + opcodes
    token_counts = Counter(tokens)
    rare_tokens = sorted(token_counts.items(), key=lambda item: item[1])
    rare_tokens = [pair[0] for pair in rare_tokens]

    # TODO: Do binary search to trim to required number of tokens

    out_gadgets = StringIO()
    for assembly_line, line in zip(assembly_lines, in_lines):
        if not any([token in assembly_line for token in rare_tokens[:-30]]):
            out_gadgets.write(line + '\n')

    out_gadgets = out_gadgets.getvalue()

    return out_gadgets


def trim_formatting(in_gadgets: str) -> str:
    out_gadgets = StringIO()
    for line in in_gadgets.splitlines():
        if (len(line) > 1) and (line[1] == 'x'):
            out_gadgets.write(line + '\n')
    return out_gadgets.getvalue()


def max_instruction_trim(in_gadgets: str, max_instructions: int) -> str:
    out_gadgets = StringIO()
    for line in in_gadgets.splitlines():
        if len(line.split(';')) <= max_instructions + 1:
            out_gadgets.write(line + '\n')
    return out_gadgets.getvalue()


def blacklist_trim(in_gadgets: str, blacklist) -> str:
    out_gadgets = StringIO()
    for line in in_gadgets.splitlines():
        tokens = line.split()
        assembly = ' '.join(tokens[2:])
        if not any([item in assembly for item in blacklist]):
            out_gadgets.write(line + '\n')
    return out_gadgets.getvalue()


def endings_trim(in_gadgets: str) -> str:
    out_gadgets = StringIO()
    endings_count = {}
    for line in in_gadgets.splitlines():
        tokens = line.split(';')
        if tokens[-1] in endings_count:
            endings_count[tokens[-1]] += 1
        else:
            endings_count[tokens[-1]] = 1
    ending = max(endings_count, key=endings_count.get)
    for line in in_gadgets.splitlines():
        tokens = line.split(';')
        if tokens[-1] == ending:
            out_gadgets.write(line + '\n')
    return out_gadgets.getvalue()


def find_syscall(in_gadgets: str) -> str:
    for line in in_gadgets.splitlines():
        if ": int 0x80" in line:
            return line


def standard_trim(in_gadgets: str) -> str:
    out_gadgets = trim_formatting(in_gadgets)
    out_gadgets = max_instruction_trim(out_gadgets, 2)
    out_gadgets = blacklist_trim(out_gadgets, ['+', '-', '*', ']'])
    out_gadgets = blacklist_trim(out_gadgets, ["0x"])
    out_gadgets = endings_trim(out_gadgets)
    out_gadgets = rare_token_trim(out_gadgets, [], 5000)
    out_gadgets += find_syscall(in_gadgets)
    return out_gadgets


def main():
    with open("../out-rop.txt", "r") as in_file:
        in_gadgets = in_file.read()
        out_gadgets = standard_trim(in_gadgets)
    with open("Trim.txt", "w") as out_file:
        out_file.write(out_gadgets)


if __name__ == "__main__":
    main()
