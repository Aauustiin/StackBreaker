import argparse
from pathlib import Path

parser = argparse.ArgumentParser(
    description="",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("--command", default="/bin/sh")
parser.add_argument("--envp", default="")
parser.add_argument("--out-rop-path", default=Path("examples/Vuln3/Vuln3-32/out-rop.txt"))
#parser.add_argument("--program", default=Path("examples/Vuln3/Vuln3-32/vuln3-32"))

def main():
    print("Hello, world!")

if __name__ == "__main__":
    main()