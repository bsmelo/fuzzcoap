#!/bin/bash
# Credits: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -p|--port)
    PORT="$2"
    shift # past argument
    shift # past value
    ;;
    -d|--debug)
    DEBUG=YES
    shift # past argument
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

# Get new folder number
if [ -z ${1+x} ]
then
    echo "Missing output folder argument. Example: out-gen/target-name"
    exit 1
else
    ls_out=`ls $1 | sort -n | tail -n 1`
    ((ls_out++))
    new_folder="$1/$ls_out"
fi

read -r -p "Should we create folder $new_folder? " response
if [[ $response == "y" ]]
then
    echo "Creating folder"
    set -x; mkdir -p $new_folder
    echo "Enabling coredump files"
    set -x; ulimit -c unlimited; set +x;
    if [ -z ${DEBUG+x} ]
    then
        bfile=python
        if [[ -z ${PORT+x} ]]
        then
            echo "Running ProcessMonitor script on default port"
            set -x; stdbuf -o 0 $bfile process_monitor_unix.py -c $new_folder/crashlist.log -l 10 -d $new_folder &> $new_folder/target.log &
        else
            echo "Running ProcessMonitor script on port ${PORT}"
            set -x; stdbuf -o 0 $bfile process_monitor_unix.py -c $new_folder/crashlist.log -l 10 -d $new_folder -p $PORT &> $new_folder/target.log &
        fi
    else
        bfile=pdb
        echo "Running ProcessMonitor script in 'DEBUG' mode on default port"
        set -x; stdbuf -o 0 $bfile process_monitor_unix.py -c $new_folder/crashlist.log -l 10 -d $new_folder 2>&1 | tee $new_folder/target.log
    fi
else
    exit 0
fi