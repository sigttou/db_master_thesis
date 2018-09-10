#!/usr/bin/env python3
import psutil
import datetime
import time

while(1):
    for p in psutil.process_iter():
        try:
            cmd = " ".join(p.cmdline())
            # if("sudo -S" in cmd or "id -u" in cmd or "grep root" in cmd or "grep win" in cmd):
            # if("nginx -c" in cmd or "nginx -s stop" in cmd):
            if("ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -p" in cmd or "sshpass -p" in cmd or
               "sshd -f /etc/ssh/sshd_test_config" in cmd or "sleep 1" in cmd):
                age = datetime.datetime.now() - datetime.datetime.fromtimestamp(p.create_time())
                if(age.seconds > 6):
                    try:
                        print(cmd + " " + str(p.pid) + " " + str(age.seconds))
                    except UnicodeEncodeError:
                        continue
                    p.kill()
        except psutil.NoSuchProcess:
            continue
    time.sleep(2)
