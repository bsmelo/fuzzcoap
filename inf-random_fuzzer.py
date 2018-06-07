# -*- coding: utf-8 -*-
import time
import getopt
import signal
import os
import sys
from collections import OrderedDict

from scapy.all import *
from scapy.contrib.coap import *

from boofuzz import pedrpc

from coap_target import Target
from fuzzer_models import *
from utils import *

##################################################################################################
# Config
##################################################################################################
##### Debug parameters
FORCE_SMALL_TC_NUM = False
RUN_ALL = False

##### General parameters
# For reproducibility
#RANDOM_SEED = "Let's fuzz CoAP!"
#random.seed(RANDOM_SEED)

##### Scapy parameters
# Use loopback interface
if not TARGET_IPV6:
    conf.L3socket = L3RawSocket

##### Probing parameters
# List of the smartness levels to run
SMART_LEVEL_LIST = [0]
# Run Common ('') and/or Large ('-L') packets?
PACKET_LEN_LIST = ['', '-L']
# Timing (in seconds)
INTERVAL_BETWEEN_REQUESTS = 0.00001
REQUEST_TIMEOUT = 0.00005
# Number of Test Cases (TCs) to run for each packet model type
HEADER_MODEL_TC_NUM = 10000
OPTION_MODEL_TC_NUM = 50

MAX_MODEL_CRASH = 50
RESPONSE_OPTIONS = [ "Location-Path", "Max-Age", "Location-Query" ]
MAX_MODEL_CRASH_RESPONSE_OPTION = 10
PROXY_OPTIONS = [ "Proxy-Uri", "Proxy-Scheme" ]
MAX_MODEL_CRASH_PROXY_OPTION = 20

# TODO: Document this
RESERVED_LIST = ["Observe", "Uri-Port", "Content-Format", "Max-Age", "Accept", "Size2", "Size1"]

def test(output_dir, host=PROCMON_DEFAULT_DST_HOST, port=PROCMON_DEFAULT_DST_PORT,
    aut_host=COAP_AUT_DEFAULT_DST_HOST , aut_port=COAP_AUT_DEFAULT_DST_PORT, aut_src_port=COAP_AUT_DEFAULT_SRC_PORT):
    my_seed = ord(os.urandom(1))
    random.seed(my_seed)
    print "Using %d as seed" % my_seed

    target_name = output_dir.split('/')[1]

    target_info = get_target_info_from_target_name(target_name, aut_host, aut_port)
    try:
        target_env = target_info['env']
    except KeyError:
        target_env = {}

    # Pass specified target parameters to the PED-RPC server
    target = Target(
        name=target_name,
        aut_host=aut_host,
        aut_port=aut_port,
        aut_src_port=aut_src_port,
        aut_heartbeat_path=target_info['heartbeat_path'],
        aut_default_uris=target_info['default_uris'],
        aut_strings=target_info.get('strings', []),
        procmon=pedrpc.Client(host, port),
        procmon_options={
            'start_commands': [target_info['start_cmd']],
            'time_to_settle': target_info['time_to_settle'],
            'env': target_env,
        },
        output_dir=output_dir,
        run_id=output_dir.split('/')[2]
    )

    bind_layers(UDP, CoAP, sport=aut_port)
    bind_layers(UDP, CoAP, dport=aut_port)
    bind_layers(UDP, CoAP, sport=aut_src_port)
    bind_layers(UDP, CoAP, dport=aut_src_port)

    mf = Fuzzer({ target_name: target })
    mf.targets[target_name].summaryfile.write("Using %d as seed\n\n" % my_seed)

    # Signal Handler defined here so we can access the files by closure
    def signal_handler(signal, frame):
        print "\nSIGINT Received"
        mf.targets[target_name].stop_target()
        sys.exit(signal)
    signal.signal(signal.SIGINT, signal_handler)

    mf.setup(target_name)

    # [ header, uint, bigger uint, uint special, uint special, uint special, empty, opaque, string, string special, string special ]
    # Random and Informed Random fuzzers have no knowledge of CoAP Options
    active_option_list = []

    models = []
    tcs = []
    optimum_models = []
    optimum_tcs = []
    reduc_models = []
    reduc_tcs = []
    for o in ['header'] + active_option_list:
        tc_num = 0
        stc_num = 0
        smodel_num = 0
        for k,v in mf.fuzz_models[target_name][o][SMART_LEVEL_LIST[0]].iteritems():
            tc_num += v[1]
            if ((o == 'header') or \
                ((o in RESERVED_LIST) and ('rs' not in k)) or \
                ((option_model[o][1] == "string") and ('ss' not in k)) or \
                ((o not in RESERVED_LIST) and (option_model[o][1] != "string") and ('Pss' not in k) and ('Sss' not in k))):
                stc_num += v[1]
                smodel_num += 1
        models.append(len(mf.fuzz_models[target_name][o][SMART_LEVEL_LIST[0]]))
        tcs.append(tc_num)
        optimum_models.append(smodel_num)
        optimum_tcs.append(stc_num)
        reduc_models.append("{0:.2f}%".format(  (float(optimum_models[-1])/models[-1])*100  ))
        reduc_tcs.append("{0:.2f}%".format(  (float(optimum_tcs[-1])/tcs[-1])*100  ))
    table_str = Table(
        Column( "Option Name",
            [ o for o in ['header'] + active_option_list ] + ["="*15, "Total"], align=ALIGN.LEFT ),
        Column( "Models", models + ["="*15, sum(models)] ),
        Column( "TCs", tcs + ["="*15, sum(tcs)] ),
        Column( "Optimum Models", optimum_models + ["="*15, sum(optimum_models)] ),
        Column( "Optimum TCs", optimum_tcs + ["="*15, sum(optimum_tcs)] ),
        Column( "% of all Models",
            reduc_models + ["="*15, "{0:.2f}%".format((float(sum(optimum_models))/sum(models))*100)] ),
        Column( "% of all TCs",
            reduc_tcs + ["="*15, "{0:.2f}%".format(  (float(sum(optimum_tcs))/sum(tcs))*100)] ),
    )
    print table_str
    mf.targets[target_name].summaryfile.write(str(table_str)+'\n\n\n')

    start = time.time()
    mf.run_header(target_name)
    time_msg = "Total Time: %.5fs" % (time.time() - start)
    print time_msg
    mf.targets[target_name].summaryfile.write(time_msg)

    mf.targets[target_name].stop_target()

    return mf

##################################################################################################
# Fuzzer Object
##################################################################################################

class Fuzzer():
    def __init__(self, targets):
        self.targets = targets
        self.target_paths = {}
        self.fuzz_models = {}
        self.info = {}
        self.total_tc = 0

    def get_total_tc(self, run_all=True):
        tc_num = 0
        for target_name in self.fuzz_models.keys():
            for option_name in self.fuzz_models[target_name].keys():
                for sl in SMART_LEVEL_LIST:
                    for model_id, model in self.fuzz_models[target_name][option_name][sl].iteritems():
                        if run_all or ((option_name == 'header') or \
                            ((option_name in RESERVED_LIST) and ('rs' not in model_id)) or \
                            ((option_model[option_name][1] == "string") and ('ss' not in model_id)) or \
                            ((option_name not in RESERVED_LIST) and (option_model[option_name][1] != "string") and ('Pss' not in model_id) and ('Sss' not in model_id))):
                            tc_num += model[1]

        return tc_num

##################################################################################################
# Fuzzer Object: Setup Functions
##################################################################################################

    def setup(self, target_name):
        self.info[target_name] = {}
        self.info[target_name]['total_active_models'] = 0

        self.targets[target_name].pedrpc_connect()
        self.targets[target_name].start_target()
        self.targets[target_name].init_known_paths()
        time.sleep(1)

        self.target_paths[target_name] = []
        kp_i = 0
        for kp in self.targets[target_name].known_paths:
            self.target_paths[target_name].append([])
            for segment in kp.split('/'):
                self.target_paths[target_name][kp_i].append((11L, segment))
            kp_i = kp_i + 1

        longest_uri = max(self.targets[target_name].known_paths, key=len)
        longest_uri_len = len(max(self.targets[target_name].known_paths, key=len))
        longest_uri_len_ext = 0
        for segment in longest_uri.split('/'):
            longest_uri_len_ext += 0 if len(segment) < 13 else (1 if len(segment) < 269 else 2)
        longest_uri_num_paths = longest_uri.count('/') + 1
        

        # 'R': Random Options (and possibly Random Payload)
        # 'EP': Empty Payload (sent to a Known Uri)
        # 'RP': Random Payload (sent to a Known Uri)
        self.fuzz_models[target_name] = OrderedDict()
        self.fuzz_models[target_name]['header'] = [ OrderedDict(), OrderedDict(), OrderedDict(), OrderedDict() ]

        # Smartness Level = 0 ---> Full Random
        self.fuzz_models[target_name]['header'][0]['EP'] = [fuzz(CoAP(token=RandBin(RandNum(0, 15)),
            options=RandEnumKeys(self.target_paths[target_name]), paymark='')
        ), HEADER_MODEL_TC_NUM] # A # generate weird packets fuzzing only the header fields, directed to the known paths
            # To force a Payload on the Full Random packet, we need a sane Token and at least one Option
        #self.fuzz_models[target_name]['header'][0]['RP'] = [fuzz(CoAP(token=RandBin(RandNum(0, 8)),
        #    options=RandEnumKeys(self.target_paths[target_name]), paymark='\xff')/Raw()
        #), HEADER_MODEL_TC_NUM] # 2 # adds a payload to the previously generated weird packet # TODO: this can be removed

        self.fuzz_models[target_name]['header'][0]['EP-L'] = [fuzz(CoAP(token=RandBin(RandNum(0, 15)),
            options=RandEnumKeys(self.target_paths[target_name]), paymark=''))/Raw(load=RandEnumKeys(
            [ RandBin(i) for i in SeqSingNum(0, 2**16-1 - (20+8) - (4+15+longest_uri_num_paths+longest_uri_len_ext+longest_uri_len), neg=False, overflow_max=False)._choice ]
        )), HEADER_MODEL_TC_NUM] # adds weird options creating packets of *any* size to the A packets
        self.fuzz_models[target_name]['header'][0]['RP-L'] = [fuzz(CoAP(token=RandBin(RandNum(0, 8)),
            options=RandEnumKeys(self.target_paths[target_name]), paymark='\xff'))/Raw(load=RandEnumKeys(
            [ RandBin(i) for i in SeqSingNum(0, 2**16-1 - (20+8) - (4+8+longest_uri_num_paths+longest_uri_len_ext+longest_uri_len+1), neg=False, overflow_max=False)._choice ]
        )), HEADER_MODEL_TC_NUM] # adds weird payloads creating packets of *any* size to the A packets


        self.info[target_name]['total_active_models'] += len(SMART_LEVEL_LIST) * len(self.fuzz_models[target_name]['header'][SMART_LEVEL_LIST[0]])

        self.total_tc = self.get_total_tc(run_all=RUN_ALL)

##################################################################################################
# Fuzzer Object: Running Functions
##################################################################################################

    def run_model(self, target_name, option_name, sl, model_id, opt_tc, msg, target_path=None):
        start = time.time()
        total_model_tc = self.fuzz_models[target_name][option_name][sl][model_id][1]

        initial_model_crash_count = self.targets[target_name].crash_count
        if option_name in RESPONSE_OPTIONS:
            max_model_crash = MAX_MODEL_CRASH_RESPONSE_OPTION
        elif option_name in PROXY_OPTIONS:
            max_model_crash = MAX_MODEL_CRASH_PROXY_OPTION
        else:
            max_model_crash = MAX_MODEL_CRASH

        for count in xrange(total_model_tc):
            self.targets[target_name].pre_send(count+1, total_model_tc, opt_tc, self.total_opt_tc, self.total_tc, msg)
            if not TARGET_IPV6:
                ans, unans = sr(IP(dst=self.targets[target_name].aut_host)/UDP(sport=self.targets[target_name].aut_src_port, dport=self.targets[target_name].aut_port)/str(self.fuzz_models[target_name][option_name][sl][model_id][0]), verbose=0, timeout=REQUEST_TIMEOUT)
            else:
                ans, unans = sr(IPv6(dst=self.targets[target_name].aut_host)/UDP(sport=self.targets[target_name].aut_src_port, dport=self.targets[target_name].aut_port)/str(self.fuzz_models[target_name][option_name][sl][model_id][0])[:1452], verbose=0, timeout=REQUEST_TIMEOUT)
            time.sleep(INTERVAL_BETWEEN_REQUESTS)
            self.targets[target_name].post_send(ans[0] if ans else unans[0], option_name, model_id, target_path, (count+1) == total_model_tc)
            opt_tc += 1

            if ( (self.targets[target_name].crash_count - initial_model_crash_count) >= max_model_crash ):
                self.total_opt_tc -= (total_model_tc - (count+1))
                self.total_tc -= (total_model_tc - (count+1))
                break

        crash_msg = "Crashes for %s model %s: %d (TCs Executed:%d/%d)" %\
            ('header' if option_name == 'header' else 'option %s' % option_name,
            model_id, (self.targets[target_name].crash_count - initial_model_crash_count),
            count+1, total_model_tc)
        self.targets[target_name].log(crash_msg)
        self.targets[target_name].summaryfile.write(crash_msg+'\n')
        # Fill out Model Results (MR) file
        self.targets[target_name].mrfile.write( "%s\t%s\t%d\t%d\t%d\t%f\n" %\
            ( option_name, model_id,
            (self.targets[target_name].crash_count - initial_model_crash_count),
            count+1, total_model_tc, (time.time() - start) ) )
        self.targets[target_name].log("="*80)

        return opt_tc

    def run_option(self, target_name, option_name, run_all=True):
        start = time.time()

        opt_tc = 1
        self.total_opt_tc = 0
        for sl in SMART_LEVEL_LIST:
            for model_id, model in self.fuzz_models[target_name][option_name][sl].iteritems():
                if run_all or ( ((option_name == 'header') or \
                    ((option_name in RESERVED_LIST) and ('rs' not in model_id)) or \
                    ((option_model[option_name][1] == "string") and ('ss' not in model_id)) or \
                    ((option_name not in RESERVED_LIST) and (option_model[option_name][1] != "string") and ('Pss' not in model_id) and ('Sss' not in model_id))) ):
                    self.total_opt_tc += model[1]

        initial_opt_crash_count = self.targets[target_name].crash_count
        for sl in SMART_LEVEL_LIST:
            for model_id, model in self.fuzz_models[target_name][option_name][sl].iteritems():
                target_path = None
                if run_all or ( ((option_name == 'header') or \
                    ((option_name in RESERVED_LIST) and ('rs' not in model_id)) or \
                    ((option_model[option_name][1] == "string") and ('ss' not in model_id)) or \
                    ((option_name not in RESERVED_LIST) and (option_model[option_name][1] != "string") and ('Pss' not in model_id) and ('Sss' not in model_id))) ):
                    msg = "Fuzzing %s | Model ID: %s | Smart Level: %d" %\
                        ('Header' if option_name == 'header' else 'Option: %s' % option_name,
                        model_id, sl)
                    if option_name != 'header' and ("KU" in model_id):
                        target_path = (self.targets[target_name].known_paths[ int(model_id.split('_')[-1]) ])
                        msg += " | Target Resource: %s" % target_path

                    opt_tc = self.run_model(target_name, option_name, sl, model_id, opt_tc, msg, target_path)


        crash_msg = "Crashes for %s: %d" %\
            ('header' if option_name == 'header' else 'option %s' % option_name,
            (self.targets[target_name].crash_count - initial_opt_crash_count))
        time_msg = "Total time for %s: %.5fs" %\
            ('header' if option_name == 'header' else 'option %s' % option_name,
            (time.time() - start))
        self.targets[target_name].log(crash_msg)
        self.targets[target_name].log(time_msg)
        self.targets[target_name].summaryfile.write(crash_msg+'\n'+time_msg+'\n\n')
        self.targets[target_name].log("Total crashes until now: %d" % (self.targets[target_name].crash_count))
        
        self.targets[target_name].log("="*120)

    def run_header(self, target_name):
        self.run_option(target_name, 'header')

##################################################################################################
# Main
##################################################################################################

USAGE = "USAGE: process_monitor_unix.py"\
        "\n    [-h|--host ipv4]                 Process Monitor's Host" \
        "\n    [-p|--port port]                 Process Monitor's TCP port"\
        "\n    [-H|--aut_host aut_ipv4]         Application Under Test's Host" \
        "\n    [-P|--aut_port aut_port]         Application Under Test's UDP port (CoAP dst)"\
        "\n    [-t|--aut_src_port aut_src_port] Target's UDP port (CoAP src)"\
        "\n    -d|--output_dir dir              directory where output files are put "\
        "\n                                     (as in 'output/<target_name>/<run_id>')"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)

if __name__ == "__main__":
    # parse command line options.
    opts = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h:p:H:P:t:d:",
            ["host=", "port=", "aut_host", "aut_port", "aut_src_port", "output_dir="] )
    except getopt.GetoptError:
        ERR(USAGE)

    host = None
    port = None
    aut_host = None
    aut_port = None
    aut_src_port = None
    coredump_dir = None
    for opt, arg in opts:
        if opt in ("-h", "--host"):
            host  = arg
        if opt in ("-p", "--port"):
            port = int(arg)
        if opt in ("-H", "--aut_host"):
            aut_host  = arg
        if opt in ("-P", "--aut_port"):
            aut_port = int(arg)
        if opt in ("-t", "--aut_src_port"):
            aut_src_port = int(arg)
        if opt in ("-d", "--output_dir"):
            output_dir = arg

    if not output_dir:
        ERR(USAGE)

    if not os.path.isdir(output_dir):
        ERR("output_dir must be an existing directory")

    if not host:
        host = PROCMON_DEFAULT_DST_HOST

    if not port:
        port = PROCMON_DEFAULT_DST_PORT

    if not aut_host:
        aut_host = COAP_AUT_DEFAULT_DST_HOST 

    if not aut_port:
        aut_port = COAP_AUT_DEFAULT_DST_PORT

    if not aut_src_port:
        aut_src_port = COAP_AUT_DEFAULT_SRC_PORT

    interact(mydict=globals(), mybanner="Informed Random Fuzzer v0.5", argv=[])
