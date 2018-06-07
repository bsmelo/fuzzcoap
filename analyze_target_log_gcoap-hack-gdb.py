import os
import code
import re
from collections import OrderedDict
import StringIO

from scapy.all import *
from scapy.contrib.coap import *

from pygdbmi.gdbcontroller import GdbController, GdbTimeoutError

from utils import *

LOWER_BOUND_FOR_PACKET_TRY_ALL = 0 #29339

if not TARGET_IPV6:
    conf.L3socket = L3RawSocket

TIME_TO_REPRODUCE = 0.00005 #2
TIME_TO_HEARTBEAT = 1.5

def heartbeat(heartbeat_path):
    # .well-known/core should work since that, even if the target doesn't support discovery, it should answer 4.04 Not Found
    if not TARGET_IPV6:
        resp = sr1(IP(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/CoAP(type=0, code=1, options=heartbeat_path), timeout=TIME_TO_HEARTBEAT, verbose=0)
    else:
        resp = sr1(IPv6(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/CoAP(type=0, code=1, options=heartbeat_path), timeout=TIME_TO_HEARTBEAT, verbose=0)
    if resp and ('IPerror' not in resp):
        # Response actually came from target, and not from IP stack (ICMP error dest/port unreachable)
        return True
    return False

##################################################################################################
# Process target.log
##################################################################################################

def process_target_log_tc(tc_report, target_report, cdcsv, target_name, full=False):
    my_key = None

    internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))

    if internal:
        return 0

    elif target_name in ['coapthon-plugtest', 'coapthon-server', 'openwsn-server']:
        if full:
            tcb_i = next((tc_report.index(s) for s in tc_report if 'Traceback' in s), None)
        if len(tc_report) >= 5 and ( ('Traceback' in tc_report[1]) or (full and tcb_i >= 0) ):
            tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)

            try:
                file_name_i = next((tc_report.index(s) for s in reversed(tc_report) if 'File "' in s), None)
                # TODO: The following indexes from tc_report may vary due to stacktrace depth
                file_name = re.search(r'"(.*?)", line (\d+)', tc_report[file_name_i]).group(1) #-3
                line_no = re.search(r'"(.*?)", line (\d+)', tc_report[file_name_i]).group(2) #-3
                full_exception = tc_report[file_name_i+2] #-1
                exception_name = re.search(r'^(.*?):', full_exception).group(1) if ':' in full_exception else full_exception.split()[0] #-1

                my_key = file_name+'|'+line_no+'|'+exception_name
            except:
                internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                if not internal:
                    print "Problem processing TC %s" % tc_no
                return -1

    elif target_name in ['jcoap-server', 'jcoap-plugtest']:
        if full:
            tcb_i = next((tc_report.index(s) for s in tc_report if 'Exception' in s), None)
        if len(tc_report) >= 4 and ( ('Exception' in tc_report[1]) or (full and tcb_i >= 0) ):
            tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)

            try:
                file_name = re.search(r'at (.*?)\((.*?)\:(\d+)\)', tc_report[tcb_i+1]).group(2)
                line_no = re.search(r'at (.*?)\((.*?)\:(\d+)\)', tc_report[tcb_i+1]).group(3)
                full_exception = "%s [%s] %s" % (' '.join(tc_report[tcb_i-1].split()[3:]) if ' '.join(tc_report[tcb_i-1].split()[3:]) else ' '.join(tc_report[tcb_i].split()[5:]),
                    tc_report[tcb_i].split()[-1], tc_report[tcb_i+1].strip())
                exception_name = tc_report[tcb_i].split()[4].strip(':')

                my_key = file_name+'|'+line_no+'|'+exception_name
            except:
                internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                if not internal:
                    print "Problem processing TC %s" % tc_no
                return -1

    elif target_name in ['ibm-crosscoap-proxy']:
        if full:
            tcb_i = next((tc_report.index(s) for s in tc_report if 'panic' in s), None)
        if len(tc_report) >= 7 and ( ('panic' in tc_report[1]) or (full and tcb_i >= 0) ):
            tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)

            try:
                file_name = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+7]).group(1).strip()
                line_no = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+7]).group(2)
                full_exception = "%s %s" % (tc_report[tcb_i].replace(':', ' -')[8:].replace('\n', ''), tc_report[tcb_i+1])
                exception_name = tc_report[tcb_i].replace(':', ' -')[8:]

                my_key = file_name+'|'+line_no+'|'+exception_name
            except:
                internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                if not internal:
                    print "Problem processing TC %s" % tc_no
                return -1

    else:
        print "Target Unknown"
        exit(-2)

    if my_key is not None:
        try:
            target_report[my_key].append(tc_no)
        except KeyError:
            target_report[my_key] = []
            target_report[my_key].append(tc_no)

        cdcsv.write( "%s\t%s\t%s\t%s\n" % (tc_no, my_key.strip('\n'), exception_name.strip('\n'), full_exception.strip('\n')) )

def get_report(target_report):
    d = OrderedDict(sorted(target_report.items(), key=lambda t: t[0]))

    return Table(
        Column( "File Name",            [ k.split('|')[0] for k in d.keys() ] + ["Total", "Unique"], align=ALIGN.LEFT ),
        Column( "Line #",               [ k.split('|')[1] for k in d.keys() ] + ['', '']),
        Column( "Exception/Function",   [ k.split('|')[2] for k in d.keys() ] + ['', ''], align=ALIGN.LEFT ),
        Column( "Failed TCs",           map(len, d.values()) + [ sum(map(len, d.values())), len(d.keys()) ] )
    )

def process_target_log(target_logfile=None, target_report={}, full=False):
    if 'target.log' not in target_logfile:
        target_logfile = target_logfile + '/target.log'

    target_info = get_target_info_from_filename(target_logfile)

    cdcsv = open('%s/%s/%s/cd.csv' % (target_logfile.split('/')[0], target_info['target_name'], target_info['run_id']), 'w')
    target_report = {}

    with open(target_logfile) as f:
        pos = 0
        while True:
            line = f.readline()
            if 'pre_send(' in line:
                tc_report = [line]
                while True:
                    pos = f.tell()
                    line = f.readline()
                    if 'pre_send(' in line or line == '':
                        break
                    tc_report.append(line)
                process_target_log_tc(tc_report, target_report, cdcsv, target_info['target_name'], full)
                f.seek(pos)
            elif line == '':
                break

    table_report = get_report(target_report)
    print table_report
    with open('%s/%s/%s/cd_summary.log' % (target_logfile.split('/')[0], target_info['target_name'], target_info['run_id']), 'w') as f:
        f.write(str(table_report))
    cdcsv.close()

##################################################################################################
# Process crashlist.log
##################################################################################################

def process_crashlist_log_tc(tc_no, target_report, cdcsv, base_folder, target_name, run_id, bin_file):
    """Debug an application's core dump file programatically

    For a list of GDB MI commands, see https://www.sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI.html
    """

    if target_name in ['libcoap-server', 'libnyoci-plugtest', 'riot-native-nanocoap-server', 'riot-native-gcoap-server', 'contiki-native-erbium-plugtest', 'mongoose-server', 'coapp-server']:
        # Initialize object that manages gdb subprocess
        gdbmi = GdbController()

        # Send gdb commands. Gdb machine interface commands are easier to script around,
        # hence the name "machine interface".
        # Responses are returned after writing, by default.

        # Load the executable file
        try:
            responses = gdbmi.write('-file-exec-and-symbols %s' % bin_file, timeout_sec=5)
        except:
            print "Could not load executable for tc %s" % tc_no
            return -1
        # Get list of source files used to compile the binary
        #responses = gdbmi.write('-file-list-exec-source-files')
        if not os.path.isfile('%s/%s/%s/TC_%s.dump' % (base_folder, target_name, run_id, tc_no)):
            print "TC %s has no core file" % tc_no
            return -1
        # Read core file
        while True:
            try:
                responses = gdbmi.write('core %s/%s/%s/TC_%s.dump' % (base_folder, target_name, run_id, tc_no), timeout_sec=5)
            except GdbTimeoutError:
                print "retrying due to timeout when opening core file for tc %s" % tc_no
                continue
            break
        # Get information from the selected (default=inner-most (0)) stack frame
        # TODO: For some reason, responses seems to have a delay or something like that
        while not (len(responses) == 1 and responses[0]['type'] == 'result' and responses[0]['payload'] is not None and 'stack' in responses[0]['payload']):
            try:
                responses = gdbmi.write('-stack-list-frames', timeout_sec=5)
            except GdbTimeoutError:
                print "retrying due to timeout when listing the stack frames for tc %s" % tc_no
                continue
        # List variable's names, types and values from the selected stack frame
        #responses = gdbmi.write('-stack-list-variables 2')

        gdbmi.exit()
        gdbmi.exit()
        gdbmi.exit()
        # gdbmi.gdb_process is None now because the gdb subprocess (and its inferior
        # program) have been terminated

        stack_list = responses[0]['payload']['stack']
        for i in xrange(len(stack_list)):
            if 'fullname' in stack_list[i] and 'coap' in stack_list[i]['fullname']:
                break
        try:
            #nanocoap hack: i = i+1
            file_name = stack_list[i]['fullname']
            function_name = stack_list[i]['func']
            line_no = stack_list[i]['line']

            my_key = file_name+'|'+line_no+'|'+function_name
        except:
            print "Problem processing TC %s" % tc_no
            return -1

        try:
            target_report[my_key].append(tc_no)
        except KeyError:
            target_report[my_key] = []
            target_report[my_key].append(tc_no)

        cdcsv.write( "%s\t%s\t%s\n" % (tc_no, my_key.strip('\n'), function_name.strip('\n')) )

def process_crashlist_log(crashlist_logfile=None, target_report={}):
    if 'crashlist.log' not in crashlist_logfile:
        crashlist_logfile = crashlist_logfile + '/crashlist.log'
    RELEVANT_TC_LIST = [1599, 8092, 14308, 24523, 29971, 28251]

    target_info = get_target_info_from_filename(crashlist_logfile)

    cdcsv = open('%s/%s/%s/cd.csv' % (crashlist_logfile.split('/')[0], target_info['target_name'], target_info['run_id']), 'w')
    target_report = {}

    with open(crashlist_logfile) as f:
        for line in f:
            if (RELEVANT_TC_LIST and (int(line.split()[5]) in RELEVANT_TC_LIST)) or (not RELEVANT_TC_LIST):
                process_crashlist_log_tc(line.split()[5], target_report, cdcsv, crashlist_logfile.split('/')[0], target_info['target_name'], target_info['run_id'], target_info['bin_file'])

    table_report = get_report(target_report)
    print table_report
    with open('%s/%s/%s/cd_summary.csv' % (crashlist_logfile.split('/')[0], target_info['target_name'], target_info['run_id']), 'w') as f:
        f.write(str(table_report))
    cdcsv.close()

##################################################################################################
# Process packets.log
##################################################################################################

def reproduce_crash(strpkt, tc_pkt, heartbeat_path, try_all):
    print "With TC: %d" % tc_pkt
    #print strpkt

    io_pkt = StringIO.StringIO(strpkt)
    sys.stdin = io_pkt
    pkt = CoAP(import_hexcap())
#    pkt = Raw(load=import_hexcap())
    sys.stdin = sys.__stdin__

    pkt.show()

    if not TARGET_IPV6:
        resp = sr1(IP(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/pkt, verbose=0, timeout=TIME_TO_REPRODUCE)
    else:
        resp = sr1(IPv6(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=COAP_AUT_DEFAULT_SRC_PORT, dport=COAP_AUT_DEFAULT_DST_PORT)/pkt, verbose=0, timeout=TIME_TO_REPRODUCE)

    if try_all:
        return False
    else:
        if not resp:
            resp = heartbeat(heartbeat_path)
        if resp:
            print "Target OK"
        else:
            print "Target Crashed"
            raw_input('Continue?')

        return not resp # False

def process_packets_log_tc(pktlog, heartbeat_path, try_all):
    reproduced = False
    tc_no = pktlog[0].split()[-1]
    if int(tc_no) > LOWER_BOUND_FOR_PACKET_TRY_ALL:
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
                reproduced = reproduce_crash(str_pkt, tc_pkt, heartbeat_path, try_all)

        # Try to reproduce through the "Last Packets sent to URI/Resource"
        if not reproduced and ( j < len(pktlog) ):
            n_last_uri = int(pktlog[j].split()[-1])
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
                    reproduced = reproduce_crash(str_pkt, tc_pkt, heartbeat_path, try_all)

        if try_all:
            time.sleep(TIME_TO_HEARTBEAT)
            if not heartbeat(heartbeat_path):
                reproduced = True
                print "Target Crashed for TC: %s" % tc_no
                raw_input('Continue?')

    else:
        print "Skipping TC: %s" % tc_no

    return reproduced

def process_packets_log(packets_logfile=None):
    if 'packets.log' not in packets_logfile:
        packets_logfile = packets_logfile + '/packets.log'
    RELEVANT_TC_LIST = []
    TRY_ALL = False
    already_read_title = False

    target_info = get_target_info_from_filename(packets_logfile)

    with open(packets_logfile, 'r') as f:
        while True:
            if not already_read_title:
                line = f.readline()
            if line == '':
                break
            if (RELEVANT_TC_LIST and (int(line.split()[-1]) in RELEVANT_TC_LIST)) or (not RELEVANT_TC_LIST):
                pktlog = [line]
                while True:
                    line = f.readline()
                    if line == '\n':
                        line = f.readline()
                        if line == '\n':
                            process_packets_log_tc(pktlog, target_info['heartbeat_path'], TRY_ALL)
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

if __name__ == "__main__":
    code.interact( local=dict(globals(), **locals()), banner="CoAP Fuzzer's Log Analyzer v0.5" )
