#!/bin/bash
BASE_FOLDER=out_m
# Get folder number
ls_out=`ls $BASE_FOLDER/$1 | sort -n | tail -n 1`
folder="$BASE_FOLDER/$1/$ls_out"

read -r -p "Should we use folder $folder? " response
if [[ $response == "y" ]]
then
    if [[ $2 == "-d" ]]
    then
        echo "Running Fuzzer in DEBUG mode"
        set -x; sudo stdbuf -o 0 pdb mut_fuzzer.py -d $folder 2>&1 | tee $folder/fuzzer.log
    else
        echo "Running Fuzzer"
        set -x; sudo python mut_fuzzer.py -d $folder
    fi
else
    exit 0
fi

# Best-effort, Highest-Prio:
# ionice -c 2 -n 0 bash
# Real-Time, Lowest-Prio:
# ionice -c 1 -n 7
# Real-Time, Medium-Prio:
# ionice -c 1 -n 3

# Medium-Prio
# sudo renice -10 -p 22972
# Highest-Prio
# sudo renice -19 -p 22972
