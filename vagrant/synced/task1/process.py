import re
import subprocess

cmd = ['nm', '-fposix', 'test']
nm = subprocess.run(cmd, stdout=subprocess.PIPE)
nmOut = nm.stdout.decode()

stdFuncPat = r'^(\w+)\s'
stdFuncPat = re.compile(stdFuncPat, re.MULTILINE)
stdFunc = stdFuncPat.findall(nmOut)
stdFunc = list(dict.fromkeys(stdFunc))

print(len(stdFunc))

file = open('std_c_functions', 'w')
for f in stdFunc:
    file.write(f + '\n')
file.close

