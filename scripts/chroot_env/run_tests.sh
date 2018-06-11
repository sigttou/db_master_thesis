#!/usr/bin/env bash

# $1 = path to skeleton chroot
# $2 = folder to place chroots
# $3 = folder to modified files
# $4 = file to be replaced
# $5 = number of parallel runs

modified_inside="/media/flips"
log_file="/tmp/succ.file"
chroot_skeleton="/var/chroot/zesty_templ/"
chroots_path="/media/ramdisk/chroot/"
cmd_file=$1
path_to_flips=$2
file_to_replace=$3
num_runs=$4
flips_per_run=$(find $path_to_flips -maxdepth 1 -type f | wc -l)
flips_per_run=$(expr $flips_per_run + $num_runs - 1)
flips_per_run=$(expr $flips_per_run / $num_runs)

if [ "$#" -ne 4 ]; then
  echo "Illegal number of parameters"
  echo "./run_tests.sh <file_to_exec> <modified_files> <file_to_replace> <number_of_parallel_runs>"
  exit 1
fi

worker () {
  local run_chroot=$1
  local run_flips=$2
  cp $cmd_file $run_chroot/ || { echo 'cp failed' ; exit 1; }
  if [ ! -e "$run_chroot$modified_inside" ]; then
    mkdir -p $run_chroot$modified_inside || { echo 'mkdir failed' ; exit 1; }
    mount --bind $run_flips $run_chroot$modified_inside || { echo 'mount failed' ; exit 1; }
  fi
  echo -e "./$cmd_file $modified_inside/ $file_to_replace $log_file" | chroot $run_chroot
  umount $run_chroot$modified_inside
  rmdir $run_chroot$modified_inside
}

echo "Preparing chroots"

for i in $(seq $num_runs);
do
  tmp_chroot=$chroots_path$i
  tmp_flips=$path_to_flips$i
  mkdir -p $tmp_flips
  find $path_to_flips -maxdepth 1 -type f | head -n $flips_per_run | xargs -i mv "{}" $tmp_flips/
  cp -R $chroot_skeleton $tmp_chroot
  echo "Generated chroot $i ..."
  worker $tmp_chroot $tmp_flips &
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
