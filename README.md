# StackBreaker

_Binary dance starts,_\
_Ropes entwine in code ballet,_\
_Stacks break, chains advance._ \
 _&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-ChatGPT_
&nbsp;\
&nbsp;

StackBreaker is an automatic exploit generation tool (AEG) based on return oriented programming (ROP).

**Kind notice** &nbsp;An OpenAi API key has been included in the code with credit of 1£. Please note that any time StackBreaker is run with the `--gpt`,&nbsp;`--gpt-assembly`, &nbsp;or `--test`&nbsp; flags credit is used up.  

## System Requirements

StackBreaker depends on the following packages:

### Vagrant

We provide a Vagrantfile that specifies a virtual environment that StackBreaker can be run inside. Setting up this virtual environment relies on vagrant and make.
- Instructions for installing Vagrant can be found here:
    - https://developer.hashicorp.com/vagrant/tutorials/getting-started/getting-started-install
- Instructions for installing Make can be found here:
    - https://inst.eecs.berkeley.edu/~cs61b/fa18/docs/make-install.html

### Python

StackBreaker requires > Python 3.10. Instructions for downloading newer Python versions can be found here https://www.python.org/downloads/.

The following Python packages are required:
- angr
   - `pip install angr`
- openai
    - `pip install --upgrade openai`

### ROPgadget

We require ROPgadget to be installed. ROPgadget can be downloaded from this URL: https://github.com/JonathanSalwan/ROPgadget. Its a github repo, so you can either clone it or (suggested) simple use "Download zip" option. Then install with:
- `sudo -H python3 -m pip install ROPgadget`

### Netcat

Some of our examples involve a reverse shell exploit that depends upon netcat.

"
Download netcat (the latest release of netcat that comes pre-installed in Ubuntu has removed a particular option (-e) that we need. Having said that, official netcat release still shipped with that option! So, we are not completely artificial ;). URL: https://sourceforge.net/projects/netcat/. However, the same is also avaialble here: https://github.com/cs-uob/COMSM0049/blob/master/docs/2021/code/nc071.tar.gz
- Untar it and build: ./configure and make command (do not do make install!)
- Move src/netcat to /tmp/nc: cp src/netcat /tmp/nc (check if the binary is working as expected /tmp/nc --help).

" - https://github.com/cs-uob/COMSM0049/blob/master/docs/labs/4.md

## Setup

### Running Inside the Vagrant Machine (Recommended)

Clone this repository, navigate into the folder named vagrant, and run `make`. This should set up the vagrant machine and install all dependencies.

### Running StackBreaker Without the Vagrant Machine

Install the dependencies outlined in System Requirements. We recommend installing Python packages inside a Python virtual environment:
- `python -m pip venv venv`
- `./venv/bin/activate`
- `pip install angr`
- `pip install --upgrade openai`

## Usage

First, navigate into vagrant/synced/StackBreaker. From here StackBreaker can be run. The following section outlines the protocol by which you specify which functionality you would like to execute with command line arguments.

| Flag | Description |
|---|---|
| --program | A path to the target binary. |
| --ROPgadget-path | A path to the ROPgadget binary. Required for all exploit generation methods, save the GPT shellcode compiler. Defaults to a usable value when using the provided vagrant machine. |
| --out-rop-path | A path to out-rop.txt, useful if you've already generated |
| --padding | When True, analysis is performed to find the amount of padding needed to overwrite a saved return address. |
| --test | When True, runs an automated testing pipeline that evaluates the correctness of the gpt-assisted shellcode to gadget compiler. |
| --end-to-end | When True, runs the target binary with the generated exploit. |
| --command | The command that should be executed via execve when generating an exploit with the execve exploit generation method. |
| --envp | Environment variables to be ran with the command mentioned above, defaults to "". |
| --input | A path to the input file from which an exploit should be generated. Relevant for use of the assembly compiler, GPT-Assisted assembly compiler, and GPT shellcode compiler. |
| --assembly | When set to True, the assembly to ROP chain compiler will be active. |
| --api-key | An API key to be used with the GPT shellcode compiler and GPT-assisted assembly compiler. Defaults to a provided key. |
| --gpt | When set to true, the GPT shellcode compiler will be active. |
| --gpt-assembly | When set to true, the GPT-assisted assembly compiler will be active. |
| --fuzz | Runs the mutational fuzzing algorithm to find an input that allows the given program to reach a vulnerable state.  |
| --drawCFG | When True, draw CFG outputs an image of the control flow dependency graph. |
| --drawCFG_simple | When True, draw CFG Simple outputs the image of a simplified control flow dependency graph. |
| --printCFGPath | When True, prints the shortest possible execution trace between the main function and the and the vulnerable function. |
| --printCallPath | When True, prints the call path from main to the vulnerable function. |

Below are some example StackBreaker calls made inside the provided vagrant machine to illustrate how to use the provided flags:
- `python3 StackBreaker.py --program=<PATH> --padding=True`
    - Runs StackBreaker with just the padding finder on the target binary.
- `python3 StackBreaker.py --program<PATH> --padding=True --end-to-end=True --command="/bin/sh"`
    - Runs the execve exploit generator with the "/bin/sh" command, and runs the exploit on the target binary.
- `python3 StackBreaker.py --program<PATH> --padding=True --end-to-end=True --assembly=True --input=<PATH>`
    - Runs the assembly to ROP chain generator with provided input, and runs the exploit on the target binary.
- `python3 StackBreaker.py --program<PATH> --padding=True --test=True --api-key=<KEY>`
    - Runs the automated testing pipeline for the GPT-assisted compiler, on the target binary. Uses a provided API key.
- `python3 StackBreaker.py --program<PATH> --padding=True --GPT=True --end-to-end=True --input=<PATH>`
    - Runs the GPT shellcode compiler on the provided input, runs the exploit on the target program, uses the default API key.
- `python3 StackBreaker.py --program<PATH> --fuzz=True`
    - Runs the mutational fuzzer on the target binary.
- `python3 StackBreaker.py --program<PATH> --drawCFG=True`
    - Outputs an image of the control flow dependency graph.
- `python3 StackBreaker.py --program<PATH> --printCFGPath=True`
    - Prints the shortest possible execution trace between the main function and the and the vulnerable function.
- `python3 StackBreaker.py --program<PATH> --drawCFG_simple=True`
    - Outputs the image of a simplified control flow dependency graph.
- `python3 StackBreaker.py --program<PATH> --printCallPath=True`
    - Prints the call path from main to the vulnerable function for the target binary.

## Troubleshooting
### vagrant synced folder
    
If the `synced` folder can not mount during `vagrant up` you may need to comment the lines
```
cd synced
# install python3.10
cd Python-3.10.13
sudo make install
cd ..
#install ROPgadget
cd ROPgadget-master
sudo -H python3 -m pip install ROPgadget
cd ..
#install netcat
cd netcat-0.7.1
./configure
make
cp src/netcat /tmp/nc
cd
```
from `setup_vagrant.sh` and try executing them manually.

---

### Unrecognised NFS

If you are running Windows, or your virtual provider is HyperV, you may need to comment the line 
```
config.vm.synced_folder "./synced", "/home/vagrant/synced", type:"nfs", nfs_udp:false
```
from `Vagrantfile`

---

### Python 3.10

The fuzzing part of StackBreaker requires `angr` to work, which in turn requires Python 3.10. In `python3 --version` does not return `Python 3.10.13`, it may need to be compiled from source manually.