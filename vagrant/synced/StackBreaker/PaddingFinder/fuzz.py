import subprocess as subp
from subprocess import PIPE
import time
import re
import psutil
import sys

program = sys.argv[1]

class MonitorProcess:
    process: subp.Popen
    pid:int
    start_time:float

    def __init__(self, cmd:[str]) -> None:
        self.process = subp.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        self.pid = self.process.pid
        self.start_time = time.time()

    def elapsedTime(self) -> float:
        return time.time() - self.start_time
    
    def getStatus(self) -> float:
        process = psutil.Process(self.pid)
        return process.status()
    
    def kill(self) -> None:
        self.process.kill()
    
cmd = [program]
mon = MonitorProcess(cmd)
print(mon.getStatus())
mon.kill()
print(mon.getStatus())