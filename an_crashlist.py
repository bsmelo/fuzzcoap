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

from pygdbmi.gdbcontroller import GdbController, GdbTimeoutError

from utils import *

# USER: Restrict the analyser to these TCs only (list of integers)
RELEVANT_TC_LIST = []

def process_crashlist_log_tc(tc_no, target_report, cdcsv, io_dir, target_name, bin_file, line):
    """Retrieve information from an application's core dump file programatically

    For a list of GDB MI commands, see https://www.sourceware.org/gdb/onlinedocs/gdb/GDB_002fMI.html
    """

    if target_name in ['libcoap-server', 'libnyoci-plugtest', 'riot-native-nanocoap-server',
        'riot-native-gcoap-server', 'contiki-native-erbium-plugtest', 'mongoose-server', 'coapp-server']:
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
        if not os.path.isfile('%s/TC_%s.dump' % (io_dir, tc_no)):
            print "TC %s has no core file" % tc_no
            return -1
        # Read core file
        while True:
            try:
                responses = gdbmi.write('core %s/TC_%s.dump' % (io_dir, tc_no), timeout_sec=5)
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

        # Well, gdbmi is just buggy afterall
        gdbmi.exit()
        gdbmi.exit()
        gdbmi.exit()
        # gdbmi.gdb_process is None now because the gdb subprocess (and its inferior
        # program) have been terminated

        # Upwards on the stacktrace (from deepest to shallowest), try to get
        # the deepest trace belonging to a coap-related file which has a function name
        my_key = None
        stack_list = responses[0]['payload']['stack']
        for frame in stack_list:
            file_name = frame.get('fullname', '')
            function_name = frame.get('func', '??')
            line_no = frame.get('line', '')
            if 'coap' in frame.get('fullname', '') and frame.get('func', '??') != '??':
                my_key = file_name+'|'+line_no+'|'+function_name
                break

        if not my_key:
            print "Problem processing TC %s" % tc_no
            return -1

        try:
            target_report[my_key].append(tc_no)
        except KeyError:
            target_report[my_key] = []
            target_report[my_key].append(tc_no)

        cdcsv.write( "%s\t%s\t%s\t%s\t\n" % (tc_no, my_key, line.strip(), '') )

##################################################################################################
# Main
##################################################################################################

USAGE = "USAGE: an_crashlist.py"\
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

    infile = io_dir + '/crashlist.log'

    target_info = get_target_info_from_target_name(target_name)

    cdcsv = open(io_dir + '/cd.csv', 'w')
    cdcsv.write( "%s\t%s\t%s\t%s\t\n" % ('CRASHED_ON', 'FAILURE_ID', 'CRASH_DETAILS_1', 'CRASH_DETAILS_2') )
    target_report = {}

    with open(infile) as f:
        for line in f:
            if (RELEVANT_TC_LIST and (int(line.split()[5]) in RELEVANT_TC_LIST)) or (not RELEVANT_TC_LIST):
                process_crashlist_log_tc(line.split()[5], target_report, cdcsv, io_dir, target_name, target_info['bin_file'], line)

    table_report = get_report(target_report)
    print table_report
    with open(io_dir + '/cd_summary.log', 'w') as f:
        f.write(str(table_report))
    cdcsv.close()
    # TODO: Merge with ftc
