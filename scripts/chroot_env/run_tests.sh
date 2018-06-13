#!/usr/bin/env bash

# $1 = script or file to exec in chroot
# $2 = dir with flipped files
# $3 = file to replace with a flipped file
# $4 = number of parallel runs

if [ "$#" -ne 4 ]; then
  echo "Illegal number of parameters"
  echo "./run_tests.sh <file_to_exec> <modified_files> <file_to_replace> <number_of_parallel_runs>"
  exit 1
fi

modified_inside="/media/flips"
log_file="/tmp/succ.file"
chroot_skeleton="/var/chroot/zesty_templ"
chroots_path="/media/ramdisk/chroot/"
cmd_file=$1
path_to_flips=$2
file_to_replace=$3
num_runs=$4
flips_per_run=$(find $path_to_flips -maxdepth 1 -type f | wc -l)
flips_per_run=$(expr $flips_per_run + $num_runs - 1)
flips_per_run=$(expr $flips_per_run / $num_runs)

echo "Preparing chroots"

for i in $(seq $num_runs);
do
  tmp_chroot=$chroots_path$i
  tmp_flips=$path_to_flips$i
  mkdir -p $tmp_flips
  find $path_to_flips -maxdepth 1 -type f | head -n $flips_per_run | xargs -i mv "{}" $tmp_flips/
  cp -R $chroot_skeleton $tmp_chroot
  echo "Generated chroot $i ..."
  ./worker.sh $tmp_chroot $tmp_flips $cmd_file $log_file $file_to_replace &
done

wait

echo "Looking for successfull flips..."

for i in $chroots_path* ; do 
  if [ -f $i$log_file ]; then
    cat $i$log_file 
  else
    echo "No successfull flip at $i"
  fi
done

echo DONE!
