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

import getopt
import os
import re
from collections import deque

from utils import *

# USER: Restrict the analyser to these TCs only (list of integers)
RELEVANT_TC_LIST = []

def process_target_log_tc(tc_report, target_report, cdcsv, target_name, last_tcs, full=False):
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

                my_key = file_name+'|'+line_no+'|'+exception_name
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

                my_key = file_name+'|'+line_no+'|'+exception_name
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

                my_key = file_name.strip('\n')+'|'+line_no.strip('\n')+'|'+exception_name.strip('\n')
            except:
                try:
                    # Some stacktraces thrown by canopus has one less line (the SIGSEGV one), so try again that way
                    file_name = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+(offset-1)]).group(1).strip()
                    line_no = re.search(r'(.*?)\:(\d+)', tc_report[tcb_i+(offset-1)]).group(2)
                    full_exception = tc_report[tcb_i].replace(':', ' -')[8:].replace('\n', '')
                    exception_name = tc_report[tcb_i].replace(':', ' -')[8:]

                    my_key = file_name.strip('\n')+'|'+line_no.strip('\n')+'|'+exception_name.strip('\n')
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

        cdcsv.write( "%s\t%s\t%s\t%s\t\n" % (tc_no, my_key.strip('\n'), full_exception.strip('\n'), '') )

##################################################################################################
# Main
##################################################################################################

USAGE = "USAGE: an_target.py"\
        "\n    -t|--target_name tname           Application/System Under Test's Identifier " \
        "\n                                     (from target_list.py)" \
        "\n    -d|--io_dir iodir                directory where output files are put, " \
        "\n                                     and input files are read from " \
        "\n                                     (as in 'output/<target_name>')"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)

if __name__ == "__main__":
    # parse command line options.
    opts = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:d:",
            ["target_name=", "io_dir="] )
    except getopt.GetoptError:
        ERR(USAGE)

    target_name = None
    io_dir = None
    for opt, arg in opts:
        if opt in ("-t", "--target_name"):
            target_name  = arg
        if opt in ("-d", "--io_dir"):
            io_dir = arg

    if not io_dir or not target_name:
        ERR(USAGE)

    if not os.path.isdir(io_dir):
        ERR("io_dir must be an existing directory")

    infile = io_dir + '/target.log'

    target_info = get_target_info_from_target_name(target_name)

    cdcsv = open(io_dir + '/cd.csv', 'w')
    cdcsv.write( "%s\t%s\t%s\t%s\t\n" % ('CRASHED_ON', 'FAILURE_ID', 'CRASH_DETAILS_1', 'CRASH_DETAILS_2') )
    target_report = {}
    last_tcs = deque(maxlen=5)

    if target_name in ['canopus-server', 'ibm-crosscoap-proxy', 'jcoap-plugtest', 'openwsn-server', 'ruby-coap-server']:
        full = True
    else:
        full = False

    with open(infile) as f:
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
                if RELEVANT_TC_LIST:
                    tc_no = re.search(r'\((\d+)\)', tc_report[0]).group(1)
                    if int(tc_no) in RELEVANT_TC_LIST:
                        process_target_log_tc(tc_report, target_report, cdcsv, target_name, last_tcs, full)
                else:
                    process_target_log_tc(tc_report, target_report, cdcsv, target_name, last_tcs, full)
                f.seek(pos)
            elif line == '':
                break

    table_report = get_report(target_report)
    print table_report
    with open(io_dir + '/cd_summary.log', 'w') as f:
        f.write(str(table_report))
    cdcsv.close()

    # TODO: Merge with CRASHLIST for samples having it as well
    #if target_name in ['canopus-server', 'ibm-crosscoap-proxy', 'ruby-coap-server']: (...)   
    # TODO: Merge with ftc
