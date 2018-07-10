#!/usr/bin/env python3
import psutil
import datetime
import time

while(1):
    for p in psutil.process_iter():
        try:
            cmd = " ".join(p.cmdline())
            if("sudo -S whoami" in cmd or "id -u" in cmd or "grep root" in cmd or "grep win" in cmd):
                age = datetime.datetime.now() - datetime.datetime.fromtimestamp(p.create_time())
                if(age.seconds > 3):
                    print(cmd + " " + str(p.pid) + " " + str(age.seconds))
                    p.kill()
        except psutil.NoSuchProcess:
            continue
    time.sleep(2)
