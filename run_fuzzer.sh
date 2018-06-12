#!/bin/bash
# Credits for the parameter parsing: https://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
# USAGE: ./run_fuzzer.sh [-d|--debug] [-pdh|--procmon-dst-host pdh] [-pdp|--procmon-dst-port pdp] [-cdh|--coap-dst-host cdh] [-cdp|--coap-dst-port cdp] [-csp|--coap-src-port csp] --engine|-e gen|smart-mut|mut|inf-random|random|g|s|m|i|r --target|-t target_name base_folder/target_name
# Defaults (from utils.py):
# --- procmon_dst_host  = "127.0.0.1"     (PROCMON_DEFAULT_DST_HOST)
# --- procmon_dst_port  = 35111           (PROCMON_DEFAULT_DST_PORT)
# --- coap_dst_host     = "127.0.0.1"     (COAP_AUT_DEFAULT_DST_HOST)
# --- coap_dst_port     = "5683"          (COAP_AUT_DEFAULT_DST_PORT)
# --- coap_src_port     = "34552"         (COAP_AUT_DEFAULT_SRC_PORT)

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
    -pdh|--procmon-dst-host)
    PMHOST="$2"
    shift # past argument
    shift # past value
    ;;
    -pdp|--procmon-dst-port)
    PMPORT="$2"
    shift # past argument
    shift # past value
    ;;
    -cdh|--coap-dst-host)
    CDHOST="$2"
    shift # past argument
    shift # past value
    ;;
    -cdp|--coap-dst-port)
    CDPORT="$2"
    shift # past argument
    shift # past value
    ;;
    -csp|--coap-src-port)
    CSPORT="$2"
    shift # past argument
    shift # past value
    ;;
    -e|--engine)
    ENGINE="$2"
    shift # past argument
    shift # past value
    ;;
    -t|--target)
    TARGET="$2"
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

# Parse engine argument
case $ENGINE in
    g|gen|generational) FUZZER_SCRIPT=gen_fuzzer.py ;;
    s|smart|smart-mut|smart-mutational) FUZZER_SCRIPT=smart-mut_fuzzer.py ;;
    m|mut|mutational) FUZZER_SCRIPT=mut_fuzzer.py ;;
    i|inf|informed|inf-rand|inf-random|informed-random) FUZZER_SCRIPT=inf-random_fuzzer.py ;;
    r|rand|random) FUZZER_SCRIPT=random_fuzzer.py ;;
    *)    # unknown option
    echo "Unknown fuzzing engine: '$ENGINE'"
    exit 1
    ;;
esac

# If empty or unset
if [ -z "$TARGET" ]
then
    echo "Missing target argument. Example: target-name"
    exit 1
fi

# Check if output folder argument exists
if [ -z "$1" ]
then
    echo "Missing output folder argument. Example: out-gen/target-name"
    exit 1
else
    # Get folder number
    ls_out=`ls $1 | sort -n | tail -n 1`
    folder="$1/$ls_out"
fi

# If empty or unset
if [ -z "$PMHOST" ]; then PMHOST=-1; fi
if [ -z "$PMPORT" ]; then PMPORT=-1; fi
if [ -z "$CDHOST" ]; then CDHOST=-1; fi
if [ -z "$CDPORT" ]; then CDPORT=-1; fi
if [ -z "$CSPORT" ]; then CSPORT=-1; fi

read -r -p "Should we use folder $folder? " response
if [[ $response == "y" ]]
then
    if [ -z ${DEBUG+x} ]
    then
        echo "Running Fuzzer"
        set -x; sudo python $FUZZER_SCRIPT --host $PMHOST --port $PMPORT --aut_host $CDHOST --aut_port $CDPORT --aut_src_port $CSPORT --output_dir $folder
    else
        echo "Running Fuzzer in DEBUG mode"
        set -x; sudo stdbuf -o 0 pdb $FUZZER_SCRIPT --host $PMHOST --port $PMPORT --aut_host $CDHOST --aut_port $CDPORT --aut_src_port $CSPORT --output_dir $folder 2>&1 | tee $folder/fuzzer.log
    fi
else
    exit 0
fi