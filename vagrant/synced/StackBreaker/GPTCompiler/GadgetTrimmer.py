#import tiktoken
from io import StringIO


def trim(in_path, out_path):
    max_instructions = 2
    operations = ["+", "-", "*"]
    endings_count = {}
    whitelist = ["int 0x80"]

    gadgets = StringIO()
    with open(in_path, 'r') as file:
        for line in file:
            tokens = line.split(';')
            if tokens[-1] in endings_count:
                endings_count[tokens[-1]] += 1
            else:
                endings_count[tokens[-1]] = 1
        ending = max(endings_count, key=endings_count.get)

        file.seek(0)
        for line in file:
            cut = False
            tokens = line.split(";")
            if "0x" in line[10:]:
                cut = True
            if tokens[-1] != ending:
                cut = True
            if any([item in line for item in whitelist]):
                cut = False
            if line.count(';') > max_instructions:
                cut = True
            if any([item in line for item in operations]):
                cut = True
            if not cut:
                gadgets.write(line)

    #enc = tiktoken.encoding_for_model("gpt-3.5-turbo-1106")
    #print(len(enc.encode(gadgets.getvalue())))

    with open(out_path, "w") as file:
        file.write(gadgets.getvalue())


if __name__ == "__main__":
    trim("../out-rop.txt", "Trim.txt")
