import getopt
import os
import StringIO

from scapy.all import *
from scapy.contrib.coap import *

from utils import *

# USER: Restrict the analyser to these TCs only (list of integers)
RELEVANT_TC_LIST = []

def reproduce_crash(strpkt, tc_pkt, heartbeat_path):
    print "With TC: %d" % tc_pkt
    #print strpkt

    io_pkt = StringIO.StringIO(strpkt)
    sys.stdin = io_pkt
    #pkt = CoAP(import_hexcap())
    pkt = Raw(load=import_hexcap())
    sys.stdin = sys.__stdin__

    #pkt.show()

    if not TARGET_IPV6:
        resp = sr1(IP(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/pkt, verbose=0, timeout=AN_PACKETS_TIME_TO_REPRODUCE)
    else:
        resp = sr1(IPv6(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/pkt, verbose=0, timeout=AN_PACKETS_TIME_TO_REPRODUCE)

    if AN_PACKETS_SEND_HEARTBEAT_AFTER_EVERY_UNANSWERED_TC and not resp:
        resp = an_heartbeat(heartbeat_path)

        if resp:
            print "Target OK"
        else:
            print "Target Crashed"
            if not AN_PACKETS_TRY_ALL_RELATED_TCS_BEFORE_CONFIRMING_REPRODUCIBILITY:
                raw_input('Please restart the SUT - Continue?')

    if AN_PACKETS_TRY_ALL_RELATED_TCS_BEFORE_CONFIRMING_REPRODUCIBILITY:
        return False
    else:
        return resp

def process_packets_log_tc(pktlog, heartbeat_path):
    reproduced = False
    tc_no = pktlog[0].split()[-1]
    if int(tc_no) > AN_PACKETS_LOWER_BOUND:
        print "Reproducing crash detected on TC: %s" % tc_no

        # Try to reproduce through the "Current Unanswered Packets"
        n_unans = int(pktlog[1].split()[-1])
        j = 2
        for i in xrange(n_unans):
            if not reproduced:
                tc_pkt = int(pktlog[j].split()[-1])
                j += 1
                str_pkt = ''
                while ( j < len(pktlog) ) and ( pktlog[j] != 'PACKET_MARK\n' ):
                    str_pkt += pktlog[j]
                    j += 1
                j += 1
                reproduced = reproduce_crash(str_pkt, tc_pkt, heartbeat_path)

        if AN_PACKETS_SUT_BETWEEN_LAST2SUT_AND_LAST2URI:
            raw_input('Please restart the SUT before we try the "Last Packets sent to URI/Resource" TCs')

        # Try to reproduce through the "Last Packets sent to URI/Resource"
        if not reproduced and ( j < len(pktlog) ):
            try:
                n_last_uri = int(pktlog[j].split()[-1])
            except ValueError:
                n_last_uri = 0
            j += 1
            for i in xrange(n_last_uri):
                if not reproduced:
                    tc_pkt = int(pktlog[j].split()[-1])
                    j += 1
                    str_pkt = ''
                    while ( j < len(pktlog) ) and ( pktlog[j] != 'PACKET_MARK\n' ):
                        str_pkt += pktlog[j]
                        j += 1
                    j += 1
                    reproduced = reproduce_crash(str_pkt, tc_pkt, heartbeat_path)

        if not AN_PACKETS_SEND_HEARTBEAT_AFTER_EVERY_UNANSWERED_TC and not an_heartbeat(heartbeat_path):
            reproduced = True
            print "Target Crashed"
            if not AN_PACKETS_TRY_ALL_RELATED_TCS_BEFORE_CONFIRMING_REPRODUCIBILITY:
                raw_input('Please restart the SUT - Continue?')
        else:
            print "Target OK"
        if AN_PACKETS_TRY_ALL_RELATED_TCS_BEFORE_CONFIRMING_REPRODUCIBILITY and reproduced:
            raw_input('Please restart the SUT - Continue?')
    else:
        print "Skipping TC: %s" % tc_no

    return reproduced, int(tc_no)

##################################################################################################
# Main
##################################################################################################

USAGE = "USAGE: an_packets.py"\
        "\n    -t|--target_name tname           Application/System Under Test's Identifier " \
        "\n                                     (from target_list.py)" \
        "\n    -d|--in_dir indir                directory where input files are read from " \
        "\n                                     (as in 'output/<target_name>')"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)

if __name__ == "__main__":
    # parse command line options.
    opts = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:d:",
            ["target_name=", "in_dir="] )
    except getopt.GetoptError:
        ERR(USAGE)

    target_name = None
    in_dir = None
    for opt, arg in opts:
        if opt in ("-t", "--target_name"):
            target_name  = arg
        if opt in ("-d", "--in_dir"):
            in_dir = arg

    if not in_dir or not target_name:
        ERR(USAGE)

    if not os.path.isdir(in_dir):
        ERR("in_dir must be an existing directory")

    infile = in_dir + '/packets.log'

    target_info = get_target_info_from_target_name(target_name)

    already_read_title = False
    last_tc_no = 0
    with open(infile, 'r') as f:
        while True:
            if not already_read_title:
                line = f.readline()
            if line == '':
                break
            try:
                tc_no = int(line.split()[-1])
            except IndexError:
                while ('Crash detected on TC' not in line) and (line != ''):
                    line = f.readline()
                tc_no = int(line.split()[-1])
            if (RELEVANT_TC_LIST and (tc_no in RELEVANT_TC_LIST)) or (not RELEVANT_TC_LIST):
                pktlog = [line]
                while True:
                    line = f.readline()
                    if line == '\n':
                        line = f.readline()
                        if line == '\n':
                            last_tc_no = process_packets_log_tc(pktlog, target_info['heartbeat_path'])[1]
                            already_read_title = False
                            break
                        else:
                            pktlog.append("PACKET_MARK\n")
                    pktlog.append(line)
            else:
                line = f.readline()
                while ('Crash detected on TC' not in line) and (line != ''):
                    line = f.readline()
                already_read_title = True
