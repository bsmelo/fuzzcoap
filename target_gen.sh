#!/bin/bash
BASE_FOLDER=out_g
# Get new folder number
ls_out=`ls $BASE_FOLDER/$1 | sort -n | tail -n 1`
((ls_out++))
new_folder="$BASE_FOLDER/$1/$ls_out"

read -r -p "Should we create folder $new_folder? " response
if [[ $response == "y" ]]
then
    echo "Creating folder"
    set -x; mkdir -p $new_folder
    echo "Enabling coredump files"
    set -x; ulimit -c unlimited; set +x;
    if [[ $2 == "-d" ]]
    then
        echo "Running ProcessMonitor script in 'DEBUG' mode"
        set -x; stdbuf -o 0 python process_monitor_unix.py -c $new_folder/crashlist.log -l 10 -d $new_folder 2>&1 | tee $new_folder/target.log
    else
        if [[ $2 == "-p" ]]
        then
            echo "Running ProcessMonitor script on port $3"
            set -x; stdbuf -o 0 python process_monitor_unix.py -c $new_folder/crashlist.log -l 10 -d $new_folder -p $3 &> $new_folder/target.log &
        else
            echo "Running ProcessMonitor script on default port"
            set -x; stdbuf -o 0 python process_monitor_unix.py -c $new_folder/crashlist.log -l 10 -d $new_folder &> $new_folder/target.log &
        fi
    fi
else
    exit 0
fi

#output
#  libcoap
#    1
#      crashlist.log
#      TC_120.dump
#      TC_131.dump
#      packets.log
#      fuzzer.log
#      target.log
