#!/usr/bin/env bash

# $1 = path to chroot
# $2 = path to modified libs
# $3 = path to lib to be replaced

if [ "$#" -ne 3 ]; then
  echo "Illegal number of parameters"
  exit
fi

str="cnt=0\n
for i in "
str+=$2
str+="* ; do\n
if ! ((\$cnt % 10)); then\n
echo \$cnt\n
fi\n
cp \$i "
str+=$3
str+="\n
su -c 'echo wrong | timeout -s 9 0.1 sudo -S whoami 2>&1 | grep root' - user\n
ret=\$?; if [[ \$ret == 0 ]]; then echo \$i; fi\n
cnt=\$((cnt+1))\n
done\n"

echo -e $str | chroot $1
