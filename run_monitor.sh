#!/bin/bash
# Credits for the parameter parsing: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
# USAGE: ./run_monitor.sh [-d|--debug] [-p|--port port_number] base_folder/target_name
# Defaults (from process_monitor_unix.py):
# --- procmon_host  = "127.0.0.1"
# --- procmon_port  = 35111

# Parse arguments
POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -d|--debug)
    DEBUG=YES
    shift # past argument
    ;;
    -p|--port)
    PORT="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

# Check if output folder argument exists
if [ -z "$1" ]
then
    echo "Missing output folder argument. Example: out-gen/target-name"
    exit 1
else
    # Get new folder number
    ls_out=`ls $1 | sort -n | tail -n 1`
    ((ls_out++))
    new_folder="$1/$ls_out"
fi

if [ -z "$PORT" ]; then PORT=35111; fi

read -r -p "Should we create folder $new_folder? " response
if [[ $response == "y" ]]
then
    echo "Creating folder"
    set -x; mkdir -p $new_folder
    echo "Enabling coredump files"
    set -x; ulimit -c unlimited; set +x;
    if [ -z ${DEBUG+x} ]
    then
        echo "Running ProcessMonitor script on port ${PORT}"
        set -x; stdbuf -o 0 python process_monitor_unix.py --crash_bin $new_folder/crashlist.log --log_level 10 --coredump_dir $new_folder --port $PORT &> $new_folder/target.log &
    else
        echo "Running ProcessMonitor script in 'DEBUG' mode on port ${PORT}"
        set -x; stdbuf -o 0 pdb process_monitor_unix.py --crash_bin $new_folder/crashlist.log --log_level 10 --coredump_dir $new_folder --port $PORT 2>&1 | tee $new_folder/target.log
    fi
else
    exit 0
fi