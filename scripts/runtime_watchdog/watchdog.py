#!/usr/bin/env python3
import psutil
import datetime
import time

while(1):
    for p in psutil.process_iter():
        try:
            cmd = " ".join(p.cmdline())
            if("sudo -S whoami" in cmd and "grep" not in cmd and "timeout" not in cmd):
                age = datetime.datetime.now() - datetime.datetime.fromtimestamp(p.create_time())
                if(age.seconds):
                    print(cmd + " " + str(p.pid) + " " + str(age.seconds))
                    if(age.seconds > 5):
                        p.kill()
        except psutil.NoSuchProcess:
            continue
    time.sleep(2)
