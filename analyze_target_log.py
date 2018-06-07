import os
import code
import re
from collections import OrderedDict
from collections import deque
import StringIO

from scapy.all import *
from scapy.contrib.coap import *

from pygdbmi.gdbcontroller import GdbController, GdbTimeoutError

from utils import *

LOWER_BOUND_FOR_PACKET_TRY_ALL = 0

if not TARGET_IPV6:
    conf.L3socket = L3RawSocket

TIME_TO_REPRODUCE = 0.00005 #2
TIME_TO_HEARTBEAT = 1.5

def heartbeat(heartbeat_path):
    # .well-known/core should work since that, even if the target doesn't support discovery, it should answer 4.04 Not Found
    if not TARGET_IPV6:
        resp = sr1(IP(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=RandShort(), dport=COAP_AUT_DEFAULT_DST_PORT)/CoAP(type=0, code=1, msg_id=RandShort(), options=heartbeat_path), timeout=TIME_TO_HEARTBEAT, verbose=0)
    else:
        resp = sr1(IPv6(dst=COAP_AUT_DEFAULT_DST_HOST)/UDP(sport=RandShort(), dport=COAP_AUT_DEFAULT_DST_PORT)/CoAP(type=0, code=1, msg_id=RandShort(), options=heartbeat_path), timeout=TIME_TO_HEARTBEAT, verbose=0)
    if resp and ('IPerror' not in resp):
        # Response actually came from target, and not from IP stack (ICMP error dest/port unreachable)
        return True
    return False

##################################################################################################
# Process target.log
##################################################################################################
nanocoap_data = []
last_tcs = deque(maxlen=5)
def process_target_log_tc(tc_report, target_report, cdcsv, target_name, full=False):
    global nanocoap_data, last_tcs
    my_key = None

    internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))

    if internal and target_name != 'java-coap-server':
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

                my_key = file_name+':'+line_no+':'+exception_name
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

                my_key = file_name+':'+line_no+':'+exception_name
            except:
                internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                if not internal:
                    print "Problem processing TC %s" % tc_no
                return -1

    elif target_name in ['java-coap-server']:
        tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)
        last_tcs.append((tc_no, tc_report))

        if ( next((tc_report.index(s) for s in tc_report if 'starting target process' in s), None) and
            not next((tc_report.index(s) for s in tc_report if 'CoAP sent' in s), None) ):
            try:
                for no, report in reversed(list(last_tcs)):
                    if len(report) > 1:
                        #TODO: instead of running reversed, run forward and if 'exception' in s, grabs details from stacktrace
                        warn_i = next((report.index(s) for s in reversed(report) if 'WARN' in s), None)
                        if warn_i:
                            full_exception = report[warn_i].strip()[9:]
                            tc_no = no
                            break
                file_name = "f"
                line_no = "n"
                exception_name = full_exception.split(':')[0]

                my_key = file_name+':'+line_no+':'+exception_name
                last_tcs.clear()
            except:
                internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                if not internal:
                    last_tcs.clear()
                    print "Problem processing TC %s" % tc_no
                return -1

    elif target_name in ['gen_coap-server']:
        tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)
        last_tcs.append((tc_no, tc_report))

        if ( next((tc_report.index(s) for s in tc_report if 'starting target process' in s), None) and
            not next((tc_report.index(s) for s in tc_report if 'unexpected massage' in s), None) and
            not next((tc_report.index(s) for s in tc_report if 'discover' in s), None) ):
            file_i = None
            try:
                for no, report in reversed(list(last_tcs)):
                    if len(report) > 7:
                        file_i = next((report.index(s) for s in report if '[{file,' in s), None)
                        if file_i:
                            tc_no = no
                            break
                file_name = re.search(r'"(.*?)"', tc_report[file_i+1]).group(1)
                line_no = re.search(r'line,(\d+)', tc_report[file_i+2]).group(1)
                exception_name = re.search(r'.*?,(.*?),', tc_report[file_i-1]).group(1)
                full_exception = ''.join([line.strip() for line in tc_report[file_i-1:file_i+3]])

                my_key = file_name+':'+line_no+':'+exception_name
                last_tcs.clear()
            except:
                internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                if not internal:
                    last_tcs.clear()
                    print "Problem processing TC %s" % tc_no
                return -1

    elif target_name in ['ibm-crosscoap-proxy', 'canopus-server']:
        if target_name == 'ibm-crosscoap-proxy':
            offset = 7
        elif target_name == 'canopus-server':
            offset = 5
        else:
            print "Target Unknown"
            exit(-2)

        if full:
            tcb_i = next((tc_report.index(s) for s in tc_report if 'panic' in s), None)
        if len(tc_report) >= 7 and ( ('panic' in tc_report[1]) or (full and tcb_i >= 0) ):
            tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)

            try:
                file_name = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+offset]).group(1).strip()
                line_no = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+offset]).group(2)
                full_exception = "%s %s" % (tc_report[tcb_i].replace(':', ' -')[8:].replace('\n', ''), tc_report[tcb_i+1].replace('\n', ''))
                exception_name = tc_report[tcb_i].replace(':', ' -')[8:]

                my_key = file_name+':'+line_no+':'+exception_name
            except:
                try:
                    # Some stacktraces thrown by canopus has one less line (the SIGSEGV one), so try again that way
                    file_name = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+(offset-1)]).group(1).strip()
                    line_no = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+(offset-1)]).group(2)
                    full_exception = tc_report[tcb_i].replace(':', ' -')[8:].replace('\n', '')
                    exception_name = tc_report[tcb_i].replace(':', ' -')[8:]

                    my_key = file_name+':'+line_no+':'+exception_name
                except:
                    internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                    if not internal:
                        print "Problem processing TC %s" % tc_no
                    return -1

    elif target_name in ['ruby-coap-server']:
        if full:
            tcb_i = next((tc_report.index(s) for s in tc_report if 'ERROR' in s), None)
        if len(tc_report) >= 4 and ( ('ERROR' in tc_report[1]) or (full and tcb_i >= 0) ):
            tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)

            try:
                file_name = re.search(r'\t(.*?):(\d+):.*?`(.*)\'', tc_report[tcb_i+2]).group(1)
                line_no = re.search(r'\t(.*?):(\d+):.*?`(.*)\'', tc_report[tcb_i+2]).group(2)
                full_exception = tc_report[tcb_i+1].strip()[:1000]
                exception_name = tc_report[tcb_i+1].split(':')[0].replace(':', '')

                my_key = file_name+':'+line_no+':'+exception_name
            except:
                internal = bool(next((tc_report.index(s) for s in tc_report if 'process_monitor_unix.py' in s), None))
                if not internal:
                    print "Problem processing TC %s" % tc_no
                return -1

    elif target_name in ['riot-native-nanocoap-server']:
        tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)
        if int(tc_no) in [1445, 1459, 1464, 1465, 1469, 1471, 1475, 1477, 1479, 1481, 1484, 1489, 1490, 1491, 1492, 1493, 1495, 1497, 1510, 1529, 1545, 1547, 1548, 1551, 1552, 1557, 1558, 1559, 1560, 1561, 1568, 1569, 1572, 1575, 1584, 1598, 1602, 1603, 1604, 1606, 1612, 1653, 1659, 1667, 1678, 1679, 1740, 1754, 1775, 1787, 1857, 1861, 1869, 1928, 1937, 1945, 1979, 2085, 2248, 2333, 2338, 2403, 2507, 2523, 2550, 2555, 2557, 2560, 2577, 2585, 2589, 2591, 2618, 17150, 20166]:
            nanocoap_data.append( (tc_no, tc_report) )
# >>> for data in nanocoap_data:
# ...   print data[1][:-29]
# ...   print "\nTC: " + data[0] + " len=" + str( len(data[1][:-29]) )
# ...   raw_input("Continue?")

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
        Column( "File Name",            [ k.split(':')[0] for k in d.keys() ] + ["Total", "Unique"], align=ALIGN.LEFT ),
        Column( "Line #",               [ k.split(':')[1] for k in d.keys() ] + ['', '']),
        Column( "Exception/Function",   [ k.split(':')[2] for k in d.keys() ] + ['', ''], align=ALIGN.LEFT ),
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

    if target_name in ['libcoap-server', 'libnyoci-plugtest', 'riot-native-nanocoap-server', 'riot-native-gcoap-server', 'contiki-native-erbium-plugtest']:
        # Initialize object that manages gdb subprocess
        gdbmi = GdbController()

        # Send gdb commands. Gdb machine interface commands are easier to script around,
        # hence the name "machine interface".
        # Responses are returned after writing, by default.

        # Load the executable file
        responses = gdbmi.write('-file-exec-and-symbols %s' % bin_file, timeout_sec=5)
        # Get list of source files used to compile the binary
        #responses = gdbmi.write('-file-list-exec-source-files')
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
        while not (len(responses) == 1 and responses[0]['type'] == 'result' and responses[0]['payload'] is not None):
            responses = gdbmi.write('-stack-info-frame', timeout_sec=5)
        # List variable's names, types and values from the selected stack frame
        #responses = gdbmi.write('-stack-list-variables 2')

        gdbmi.exit()
        gdbmi.exit()
        gdbmi.exit()
        # gdbmi.gdb_process is None now because the gdb subprocess (and its inferior
        # program) have been terminated

        try:
            file_name = responses[0]['payload']['frame']['fullname']
            function_name = responses[0]['payload']['frame']['func']
            line_no = responses[0]['payload']['frame']['line']

            my_key = file_name+':'+line_no+':'+function_name
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
    target_info = get_target_info_from_filename(crashlist_logfile)

    cdcsv = open('%s/%s/%s/cd.csv' % (crashlist_logfile.split('/')[0], target_info['target_name'], target_info['run_id']), 'w')
    target_report = {}

    with open(crashlist_logfile) as f:
        for line in f:
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
    #if tc_pkt not in [172, 173]:
    #    return False
    #print strpkt

    io_pkt = StringIO.StringIO(strpkt)
    sys.stdin = io_pkt
#    pkt = CoAP(import_hexcap())
    pkt = Raw(load=import_hexcap())
    sys.stdin = sys.__stdin__

#    pkt.show()

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
            #raw_input('Continue?')
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
    RELEVANT_TC_LIST = [21235, 75507, 75512, 164917, 164922, 184433, 184438, 214071, 214076, 214081, 242432, 299093]
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
