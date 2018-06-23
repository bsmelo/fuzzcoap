# Copyright (C) 2018  Bruno Melo <brunom@lasca.ic.unicamp.br>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from collections import OrderedDict

from target_list import *

from scapy.all import *
from scapy.contrib.coap import *

# USER: Target runs on IPv6?
TARGET_IPV6 = False

# Default communication addresses (hosts and ports)
PROCMON_DEFAULT_DST_HOST = "127.0.0.1"
PROCMON_DEFAULT_DST_PORT = 35111
if TARGET_IPV6:
    # USER: Choose between RIOT and Contiki (leave only one uncommented)

    # RIOT: This IP address changes everytime the tap interface is recreated
    # USER: It needs to be obtained after executing the steps in target_list.py (for the RIOT OS targets),
    # by running any of the RIOT OS targets, such as using:
    # /home/vagrant/coap-apps/RIOT/tests/pkg_microcoap/bin/native/tests_pkg_microcoap.elf tap0
    # You'll be able to see the address in the screen (the one marked with 'scope: global'); just copy and paste here
    COAP_AUT_DEFAULT_DST_HOST = "2001:db8:1:0:48fa:4dff:fea5:9879"

    # Contiki: This IP address is fixed
    #COAP_AUT_DEFAULT_DST_HOST = "fd00::302:304:506:708"
    #conf.route6.ifdel("wlan0") # Contiki hack
else:
    COAP_AUT_DEFAULT_DST_HOST = "127.0.0.1"
    # Use loopback interface on Scapy
    conf.L3socket = L3RawSocket
COAP_AUT_DEFAULT_DST_PORT = 5683
COAP_AUT_DEFAULT_SRC_PORT = 34552

# USER: Probing parameters
# Heuristic #2 (Reduce the number of duplicated failures) - Thresholds
MAX_MODEL_CRASH = 50 # Mut (5), Others (50)
RESPONSE_OPTIONS = [ "Location-Path", "Max-Age", "Location-Query" ]
MAX_MODEL_CRASH_RESPONSE_OPTION = 10 # Smart (50), Mut (1), Others (10)
PROXY_OPTIONS = [ "Proxy-Uri", "Proxy-Scheme" ]
MAX_MODEL_CRASH_PROXY_OPTION = 20 # Smart (50), Mut (2), Others (20)
# Timing (in seconds)
INTERVAL_BETWEEN_REQUESTS = 0.00001 # Time to sleep between each Test Case (TC) sent to the SUT
REQUEST_TIMEOUT = 0.00005 # Timeout for each TC sent to the SUT
# Fuzzing Engine-specific parameters
# Number of TCs to run for each packet model type (packet template/generator)
K_RANDOM = 20000
K_INF_RANDOM = 10000
K_MUT = 100
K_ALL_GEN = 1000 # Number of TCs for the AllFields packet template/generator (Generational Fuzzer)
K_GEN = 50 # Number of TCs for the <Format>Random packet templates/generators (Generational Fuzzer)
# K_O_FORMAT, K_O_OPT_R and K_O_OPT_S are defined at runtime inside the Generational Fuzzer

# USER: Debug parameters
GEN_ALL = False # Generates all *rs*, *rr* and *ss* TCs (Generational Fuzzer)

# USER: an_packets*.py parameters
AN_PACKETS_LOWER_BOUND = 0 # Try to reproduce from TCs starting at this number
AN_PACKETS_SUT_BETWEEN_LAST2SUT_AND_LAST2URI = False # Restart SUT before trying the "last sent to uri" packets
AN_PACKETS_TIME_TO_REPRODUCE = 0.00005 # Timeout for each packet sent to the SUT
AN_PACKETS_TIME_TO_HEARTBEAT = 1 # Timeout for the heartbeat packets sent to the SUT
AN_PACKETS_LIBCOAP_HEARTBEAT = False # Send heartbeat packets with libcoap `coap-client` instead of scapy
AN_PACKETS_TRY_HEARTBEAT_TIMES = 1 # Number of heartbeat tries
AN_PACKETS_RAND_SRC = False # Randomize src port (TCs and heartbeats) and msg_id (heartbeats)
if AN_PACKETS_RAND_SRC:
    COAP_AUT_DEFAULT_SRC_PORT = RandShort()
    COAP_AUT_DEFAULT_SRC_MSG_ID = RandShort()
else:
    COAP_AUT_DEFAULT_SRC_MSG_ID = 0
AN_PACKETS_SEND_HEARTBEAT_AFTER_EVERY_UNANSWERED_TC = False # Self explanatory
AN_PACKETS_TRY_ALL_RELATED_TCS_BEFORE_CONFIRMING_REPRODUCIBILITY = True # Self explanatory

def an_heartbeat(heartbeat_path):
    if AN_PACKETS_LIBCOAP_HEARTBEAT:
        for i in range(AN_PACKETS_TRY_HEARTBEAT_TIMES):
            resp = subprocess.check_output(["coap-client", "-B", str(AN_PACKETS_TIME_TO_HEARTBEAT * (i+1)), "-v", "7", "-m", "get", "coap://localhost/.well-known/core"], preexec_fn=demote(1000, 1000))
            if 'response' in resp:
                return True
    else:
        for i in range(AN_PACKETS_TRY_HEARTBEAT_TIMES):
            if not TARGET_IPV6:
                resp = sr1(IP(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/CoAP(type=0, code=1, msg_id=COAP_AUT_DEFAULT_SRC_MSG_ID, options=heartbeat_path), timeout=AN_PACKETS_TIME_TO_HEARTBEAT, verbose=0)
            else:
                resp = sr1(IPv6(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/CoAP(type=0, code=1, msg_id=COAP_AUT_DEFAULT_SRC_MSG_ID, options=heartbeat_path), timeout=AN_PACKETS_TIME_TO_HEARTBEAT, verbose=0)
            if resp and ('IPerror' not in resp):
                # Response actually came from target, and not from IP stack (ICMP error dest/port unreachable)
                return True
    return False

# Start: https://stackoverflow.com/a/3685352
class ALIGN:
    LEFT, RIGHT = '-', ''

class Column(list):
    def __init__(self, name, data, align=ALIGN.RIGHT):
        list.__init__(self, data)
        self.name = name
        width = max(len(str(x)) for x in data + [name])
        self.format = ' %%%s%ds ' % (align, width)

class Table:
    def __init__(self, *columns):
        self.columns = columns
        self.length = max(len(x) for x in columns)
    def get_row(self, i=None):
        for x in self.columns:
            if i is None:
                yield x.format % x.name
            else:
                yield x.format % x[i]
    def get_rows(self):
        yield ' '.join(self.get_row(None))
        for i in range(0, self.length):
            yield ' '.join(self.get_row(i))

    def __str__(self):
        return '\n'.join(self.get_rows())   
# End: https://stackoverflow.com/a/3685352

def get_report(target_report):
    d = OrderedDict(sorted(target_report.items(), key=lambda t: t[0]))

    return Table(
        Column( "File Name",            [ k.split('|')[0] for k in d.keys() ] + ["Total", "Unique"], align=ALIGN.LEFT ),
        Column( "Line #",               [ k.split('|')[1] for k in d.keys() ] + ['', '']),
        Column( "Exception/Function",   [ k.split('|')[2] for k in d.keys() ] + ['', ''], align=ALIGN.LEFT ),
        Column( "Failed TCs",           map(len, d.values()) + [ sum(map(len, d.values())), len(d.keys()) ] )
    )

def californium_replace_port(aut_port):
    try:
        cf_prop = 'Californium.properties'
        os.rename(cf_prop, cf_prop+'~')
        with open(cf_prop+'~', 'r') as src_f, open(cf_prop, 'w') as dst_f:
            for line in src_f:
                if 'COAP_PORT' in line:
                    dst_f.write("COAP_PORT=%d\n" % aut_port)
                else:
                    dst_f.write(line)
        os.remove(cf_prop+'~')
    except:
        print "Couldn't find Californium.properties file to set CoAP Port.\n"\
            "Using default CoAP Port = %d" % COAP_AUT_DEFAULT_DST_PORT
        pass

def get_target_info_from_target_name(target_name, aut_host='', aut_port=-1):
    try:
        target_info = get_target_info_list(target_name, aut_host, aut_port)

        # Californium target port number need to be set in the .properties file
        if 'californium' in target_name:
            californium_replace_port(aut_port)
    except KeyError:
        print "Target Unknown"
        exit(1)

    return target_info

def get_target_info_from_filename(filename):
    target_info = {}

    if not filename:
        print "File not supplied"
        exit(1)

    try:
        target_info['target_name'] = filename.split('/')[1]
        target_info['run_id'] = filename.split('/')[2]
    except:
        print "Non-compliant filepath"
        exit(1)

    target_info.update( get_target_info_from_target_name(target_info['target_name']) )

    return target_info
