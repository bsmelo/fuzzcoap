import code
import re
from collections import OrderedDict
import StringIO
import os, shlex, subprocess

from scapy.all import *
from scapy.contrib.coap import *

from pygdbmi.gdbcontroller import GdbController, GdbTimeoutError

from utils import *

PACKETS = True
if PACKETS:
    LOWER_BOUND_FOR_PACKET_TRY_ALL = 0

    if not TARGET_IPV6:
        conf.L3socket = L3RawSocket

    def demote(user_uid, user_gid):
        def result():
            os.setgid(1000)
            os.setuid(1000)
        return result

    TIME_TO_REPRODUCE = 1
    TIME_TO_HEARTBEAT = 3
    LIBCOAP_HEARTBEAT = True
    RETRY_HEARTBEAT = 3

    SUT_START_COMMAND = "java -Dlog4j.configurationFile=file:/home/bruno/Dropbox/coap-apps/jcoap_new/ws4d-jcoap-applications/src/log4j2.xml -cp /home/bruno/Dropbox/coap-apps/jcoap_new/ws4d-jcoap-plugtest/src/:/home/bruno/Dropbox/coap-apps/jcoap_new/ws4d-jcoap/bin/:/home/bruno/Dropbox/coap-apps/jcoap_new/ws4d-jcoap/target/jcoap-core-1.1.5.jar:/home/bruno/.m2/repository/org/apache/logging/log4j/log4j-api/2.6.1/log4j-api-2.6.1.jar:/home/bruno/.m2/repository/org/apache/logging/log4j/log4j-core/2.6.1/log4j-core-2.6.1.jar:/home/bruno/.m2/repository/commons-cli/commons-cli/1.3.1/commons-cli-1.3.1.jar:/home/bruno/.m2/repository/httpcomponents-asyncclient-4.1.3/lib/httpcore-nio-4.4.6.jar:/home/bruno/.m2/repository/httpcomponents-asyncclient-4.1.3/lib/httpcore-4.4.6.jar:/home/bruno/.m2/repository/httpcomponents-asyncclient-4.1.3/lib/httpasyncclient-4.1.3.jar:/home/bruno/.m2/repository/httpcomponents-asyncclient-4.1.3/lib/httpclient-4.5.3.jar:/home/bruno/.m2/repository/commons-logging/commons-logging/1.2/commons-logging-1.2.jar:/home/bruno/.m2/repository/commons-logging/commons-logging-api/1.1/commons-logging-api-1.1.jar:/home/bruno/.m2/repository/net/sf/ehcache/ehcache/2.10.2.2.21/ehcache-2.10.2.2.21.jar:/home/bruno/.m2/repository/commons-codec/commons-codec/1.9/commons-codec-1.9.jar:/home/bruno/.m2/repository/org/slf4j/slf4j-api/1.7.7/slf4j-api-1.7.7.jar org.ws4d.coap.test.PlugtestServer"

    args = shlex.split(SUT_START_COMMAND)

    sut_log = open('temp_sut_output.log', 'w+b')
    sut = subprocess.Popen(args, preexec_fn=demote(1000, 1000), stdout=sut_log, stderr=subprocess.STDOUT)

    reproduced_data = []
#>>> for rep_data in reproduced_data:
#...   print rep_data[0] + '\n\n'
#...   print '\n'.join(rep_data[1].split('\n')[-10:])
#...   raw_input("Next")

def heartbeat(heartbeat_path):
    if LIBCOAP_HEARTBEAT:
        for i in range(RETRY_HEARTBEAT):
            resp = subprocess.check_output(["coap-client", "-B", str(TIME_TO_HEARTBEAT * (i+1)), "-v", "7", "-m", "get", "coap://localhost/.well-known/core"], preexec_fn=demote(1000, 1000))
            if 'response' in resp:
                return True
    else:
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

                my_key = file_name+':'+line_no+':'+exception_name
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

    if target_name in ['libcoap-server', 'libnyoci-plugtest', 'riot-native-gcoap-server', 'riot-native-nanocoap-server']:
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
        else:
            print "Target Crashed"
            raw_input('Continue?')

        return not resp # False

def process_packets_log_tc(pktlog, heartbeat_path, try_all):
    global sut, sut_log, reproduced_data
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
            if not heartbeat(heartbeat_path):
                time.sleep(10) # give some time to the SUT to spit out logs
                sut_log.seek(max(-sut_log.tell(), -1500), 2)
                recent_log = sut_log.read()

                if "Exception" in recent_log:
                    reproduced = True
                    reproduced_data.append((tc_no, recent_log))
                    print "################################################ Target Crashed for TC: %s" % tc_no
                    sut.kill()
                    sut = subprocess.Popen(args, preexec_fn=demote(1000, 1000), stdout=sut_log, stderr=subprocess.STDOUT)
                    time.sleep(1)
                    #raw_input('Continue?')
                else:
                    print "Target OK"

    else:
        print "Skipping TC: %s" % tc_no

    return reproduced

def process_packets_log(packets_logfile=None):
    if 'packets.log' not in packets_logfile:
        packets_logfile = packets_logfile + '/packets.log'
    RELEVANT_TC_LIST = [73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 562, 563, 564, 565, 566, 983, 1645, 1646, 1647, 1648, 2922, 6469, 6858, 6859, 6861, 6862, 6864, 6865, 6867, 6868, 6870, 6871, 6873, 6874, 6879, 6880, 6882, 6885, 6886, 6888, 6889, 6890, 6897, 6898, 6900, 6901, 6903, 6904, 6906, 6907, 6909, 6912, 6973, 6974, 6976, 6977, 6979, 6982, 6983, 6985, 6986, 6991, 6992, 6994, 6995, 6997, 6998, 7000, 7001, 7006, 7007, 7009, 7010, 7012, 7013, 7018, 7019, 7021, 7022, 7024, 7025, 7027, 7693, 7694, 8489, 8490, 8913, 8914, 8916, 8919, 8920, 8922, 8923, 8925, 8926, 8928, 8929, 8931, 8932, 8934, 8935, 8937, 8938, 8940, 8941, 8943, 8944, 8946, 8947, 8949, 8950, 8952, 8953, 8955, 8956, 8958, 8959, 8961, 8962, 9018, 9019, 9021, 9022, 9024, 9025, 9027, 9028, 9030, 9031, 9033, 9034, 9036, 9037, 9039, 9040, 9045, 9046, 9048, 9049, 9051, 9052, 9054, 9055, 9057, 9058, 9063, 9065, 9066, 9067, 9069, 9070, 9127, 9128, 9130, 9131, 9133, 9134, 9136, 9137, 9139, 9140, 9142, 9143, 9145, 9146, 9148, 9149, 9151, 9152, 9154, 9155, 9157, 9158, 9160, 9166, 9167, 9169, 9170, 9172, 9178, 9179, 9181, 9237, 9238, 9240, 9241, 9243, 9246, 9247, 9249, 9250, 9252, 9253, 9255, 9256, 9258, 9259, 9261, 9262, 9264, 9265, 9267, 9268, 9270, 9271, 9273, 9274, 9276, 9277, 9279, 9280, 9282, 9283, 9285, 9286, 9340, 9342, 9343, 9345, 9346, 9348, 9349, 11232, 11234, 11237, 11238, 11240, 11241, 11243, 11299, 11300, 11302, 11303, 11305, 11306, 11308, 11309, 11311, 11312, 11314, 11317, 11318, 11320, 11321, 11323, 11324, 11326, 11327, 11332, 11333, 11335, 11336, 11338, 11339, 11341, 11342, 11344, 11345, 11350, 11351, 11406, 11408, 11409, 11411, 11412, 11414, 11415, 11644, 11645, 12243, 12287, 12288, 12289, 12290, 12291, 12292, 12293, 12294, 12329, 12330, 12331, 12332, 12333, 12334, 12335, 12336, 12585, 12590, 12595, 12600, 12605, 12610, 12615, 12620, 12625, 12630, 12635, 12640, 12645, 12650, 12655, 12660, 12665, 12670, 12675, 12685, 12690, 12695, 12700, 12705, 12710, 12715, 12720, 12725, 12730, 12735, 12740, 12745, 12750, 12755, 12760, 12765, 12770, 12775, 12844, 12989, 12991, 12992, 12996, 12997, 13001, 13002, 13006, 13007, 13011, 13012, 13016, 13017, 13021, 13022, 13026, 13027, 13031, 13032, 13036, 13037, 13041, 13042, 13046, 13047, 13745, 13750, 13755, 13760, 13765, 13770, 13775, 13780, 13785, 13790, 13795, 13800, 13805, 13810, 13815, 13820, 13825, 13830, 13835, 13845, 13850, 13855, 13860, 13865, 13870, 13875, 13880, 13885, 13890, 13895, 13900, 13905, 13910, 13915, 13920, 13925, 13930, 13935, 14004, 14009, 14014, 14019, 14024, 14029, 14034, 14039, 14044, 14049, 14194, 14196, 14197, 14201, 14202, 14206, 14207, 14211, 14212, 14216, 14217, 14221, 14222, 14226, 14227, 14231, 14232, 14236, 14237, 14241, 14242, 14246, 14247, 14251, 14252, 14256, 14257, 14261, 14262, 14266, 14267, 14271]
    TRY_ALL = True
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
