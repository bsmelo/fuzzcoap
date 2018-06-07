import time
from collections import deque

from boofuzz import pedrpc

from scapy.all import *
from scapy.contrib.coap import *

from coapthon.client.helperclient import HelperClient
from coapthon import defines

from fuzzer_models import *

# Number of unanswered packets before sending a heartbeat
MAX_UNANS = 5
# Number [to be kept] of packets sent to specific path
MAX_TO_PATH = 5
# Number [to be kept] of packets last sent to the SUT
MAX_LAST_SENT = 5
# Time to wait on client-side (in addition to the server-side wait time) for an AUT to be up and running
TIME_TO_SETTLE = 0
TIME_TO_SELF_RECOVER = 10
TIME_TO_RECOVER_FROM_POSSIBLE_BENIGN_EXCEPTION = 5

class Target(object):
    """Target descriptor container.

    Encapsulates pedrpc connection logic.

    Example:
        tcp_target = Target('CoAPthon', procmon=pedrpc.Client(host='127.0.0.1', port=17971))
    """

    #TODO: Fix argument order, and non-defaults for files and run_id
    def __init__(self, name, aut_host="127.0.0.1", aut_port=5683, aut_src_port=34552,
        aut_heartbeat_path=None,
        aut_default_uris=None,
        aut_strings=None,
        procmon=None, procmon_options=None,
        output_dir=None, run_id=None):
        self.log_level = 10 #TODO: fix this

        self.name = name
        self.aut_host = aut_host
        self.aut_port = aut_port
        self.aut_src_port = aut_src_port
        self.aut_heartbeat_path = aut_heartbeat_path
        self.aut_default_uris = aut_default_uris

        self.procmon = procmon

        self.output_dir = output_dir
        self.summaryfile = open(output_dir+'/summary.log', 'w')
        self.pcapfile = open(output_dir+'/packets.log', 'w')
        self.invfile = open(output_dir+'/invalid.log', 'w')
        self.mrfile = open(output_dir+'/mr.csv', 'w')
        self.ftcfile = open(output_dir+'/ftc.csv', 'w')
        self.mutfile = open(output_dir+'/mutations.csv', 'w')
        self.run_id = run_id

        self.current_tc = 1
        self.crash_count = 0
        self.current_unans = []
        self.last_to_path = {}
        self.last_sent = deque(maxlen=MAX_LAST_SENT)
        self.known_paths = []
        self.opt_ext_list = {
            # type:     extension_list
            "empty":    [],
            "uint":     [],
            "string":   aut_strings,
            "opaque":   [],
        }

        if procmon_options is None:
            procmon_options = {}
        self.procmon_options = procmon_options

    def log(self, msg="", level=1):
        """
        If the supplied message falls under the current log level, print the specified message to screen.

        @type  msg: str
        @param msg: Message to log
        """

        if self.log_level >= level:
            print "[%s] %s" % (time.strftime("%H:%M.%S"), msg)

    def pedrpc_connect(self):
        """
        Pass specified target parameters to the PED-RPC server.
        """

        # If the process monitor is alive, set it's options
        self.log("Connecting to AUT's Process Monitor...")
        if self.procmon:
            while 1:
                if self.procmon.alive():
                    break

#                time.sleep(1)

            # connection established.
            for key, value in self.procmon_options.items():
                getattr(self.procmon, 'set_{0}'.format(key))(value)
        self.log("... Connected!")

    def start_target(self):
        """
        Start the fuzz target.
        """

        # If the process monitor is alive, start the target application
        self.log("Starting AUT...")
        if self.procmon:
            self.procmon.start_target()
        self.log("... Started!")

    def stop_target(self):
        """
        Stop the fuzz target.
        """

        # If the process monitor is alive, stop the target application
        self.log("Stopping AUT...")
        if self.procmon:
            self.procmon.stop_target()
        self.log("... Stopped!")

        if self.summaryfile and not self.summaryfile.closed:
            self.summaryfile.close()
        if self.pcapfile and not self.pcapfile.closed:
            self.pcapfile.close()
        if self.invfile and not self.invfile.closed:
            self.invfile.close()
        if self.mrfile and not self.mrfile.closed:
            self.mrfile.close()
        if self.ftcfile and not self.ftcfile.closed:
            self.ftcfile.close()
        if self.mutfile and not self.mutfile.closed:
            self.mutfile.close()

    def poll_pedrpc(self):
        """
        Poll the PED-RPC endpoints (netmon, procmon etc...) for the target.
        @type  target: Target
        @param target: Session target whose PED-RPC services we are polling
        """

        # check if our fuzz crashed the target. procmon.post_send() returns False if the target crashes.
        if self.procmon:
            if self.procmon.post_send():
                return True
            else:
                self.log("procmon detected crash on test case #{0}: {1}".format(self.current_tc, self.procmon.get_crash_synopsis()))

        return False

    def restart_target(self):
        """
        Restart the fuzz target. If a VMControl is available revert the snapshot, if a process monitor is available
        restart the target process. Otherwise, do nothing.
        @type  target: session.target
        @param target: Target we are restarting
        @raise sex.BoofuzzRestartFailedError if restart fails.
        """

        self.current_unans = []
        self.last_to_path = {}
        self.last_sent = deque(maxlen=MAX_LAST_SENT)

        # if we have a connected process monitor, restart the target process.
        if self.procmon:
            self.log("restarting target process")
            if not self.procmon.restart_target():
                #raise sex.BoofuzzRestartFailedError()
                self.log("ERROR RESTARTING TARGET")

            if TIME_TO_SETTLE:
                self.log("giving the process %d seconds to settle in" % TIME_TO_SETTLE)
                time.sleep(TIME_TO_SETTLE)

        # otherwise all we can do is wait a while for the target to recover on its own.
        else:
            self.log("no reset handler available... sleeping for %d seconds" % TIME_TO_SELF_RECOVER)
            time.sleep(TIME_TO_SELF_RECOVER)

        # pass specified target parameters to the PED-RPC server to re-establish connections.
        self.pedrpc_connect()

    def init_known_paths(self):
        # TODO: Instead of hack per app, receive flag from target_list.py
        self.known_paths = []
        extracted_strings = []
        response = None

        self.log("Extracting paths from AUT...")
        self.log(str(self.opt_ext_list["string"]))
        self.summaryfile.write("AUT-specific Strings:\n"+str(self.opt_ext_list["string"])+'\n')

        # Comment below for Contiki or Canopus hack
        client = HelperClient(server=(self.aut_host, self.aut_port))
        try:
           response = client.discover(timeout=5)
        except:
           self.log("Target doesn't implement discovery through GET .well-known/core")
           pass
        # Uncomment below for Contiki or Canopus hack
        # class HackResp(object):
        #     code = defines.Codes.CONTENT.number
        #     # Contiki:
        #     # payload = '</.well-known/core>;ct=40,</test>;title="Default test resource",</validate>;title="Validation test resource",</create1>;title="Creates on PUT",</create2>;title="Creates on POST",</create3>;title="Default test resource",</seg1/seg2/seg3>;title="Long path resource",</query>;title="Resource accepting query parameters",</location-query>;title="Resource accepting query parameters",</multi-format>;title="Resource providing text/plain and application/xml";ct="0 41",</link1>;rt="Type1 Type2";if="If1",</link2>;rt="Type2 Type3";if="If2",</link3>;rt="Type1 Type3";if="foo",</path>;title="Path test resource";ct="40",</separate>;title="Resource which cannot be served immediately and which cannot be acknowledged in a piggy-backed way",</large>;title="Large resource";rt="block";sz="2012",</large-update>;title="Large resource that can be updated using PUT method";rt="block";sz="2048",</large-create>;title="Large resource that can be created using POST method";rt="block",</obs>;title="Observable resource which changes every 5 seconds";obs,</mirror>;title="Returns your decoded message";rt="Debug"'
        #     # Canopus:
        #     payload = '</hello>,</basic>,</basic/json>,</watch/this>,</blockupload>,</.well-known/core>'
        # response = HackResp()

        if response and response.payload and (response.code != defines.Codes.NOT_FOUND.number):
            self.known_paths.extend([ path.strip('/') for path in re.findall(r'<(.*?)>', response.payload) ])
            if '' in self.known_paths:
                self.known_paths.remove('')

            extracted_strings = list( set( re.split( ',|;', re.sub(r'<(.*?)>', '', response.payload) ) ) )
            if '' in extracted_strings:
                extracted_strings.remove('')
            self.opt_ext_list["string"].extend(extracted_strings)

        self.known_paths.extend(self.aut_default_uris)
        self.known_paths = list( set(self.known_paths) )
        time.sleep(1)

        self.log(str(self.known_paths))
        self.summaryfile.write("Extracted Paths:\n"+str(self.known_paths)+'\n')

        self.log(str(extracted_strings))
        self.summaryfile.write("Extracted Strings:\n"+str(extracted_strings)+'\n\n\n')

        time.sleep(1)

        # Comment below for Contiki or Canopus hack
        client.stop()

    def get_mutated_value(self, option_name, model_id, rendered_pkt):
        if option_name == 'header':
            if model_id == 'MID':
                return "msg_id=%d\t" % rendered_pkt.msg_id
            elif model_id == 'TKN':
                return "tkn=%s\t%d" % (str(rendered_pkt.token), len(rendered_pkt.token))
        else:
            ret = []
            mutant_value_len = 0
            for opt in rendered_pkt.options:
                if opt[0] == option_name or opt[0] == option_model[option_name][0]:
                    try:
                        mutant_value_len += len(opt[1])
                        ret.append( "%s=%s" % ( option_name, str(opt[1]) ) )
                    except:
                        self.log("Could not get options")
                        pass
            return "%s\t%d" % (repr(ret), mutant_value_len)

        return None

    def heartbeat(self):
        # .well-known/core should work since that, even if the target doesn't support discovery, it should answer 4.04 Not Found
        if not TARGET_IPV6:
            resp = sr1(IP(dst=self.aut_host)/UDP(sport=RandShort(), dport=self.aut_port)/CoAP(type=0, code=1, msg_id=RandShort(), options=self.aut_heartbeat_path), timeout=TIME_TO_RECOVER_FROM_POSSIBLE_BENIGN_EXCEPTION, verbose=0)
        else:
            resp = sr1(IPv6(dst=self.aut_host)/UDP(sport=RandShort(), dport=self.aut_port)/CoAP(type=0, code=1, msg_id=RandShort(), options=self.aut_heartbeat_path), timeout=TIME_TO_RECOVER_FROM_POSSIBLE_BENIGN_EXCEPTION, verbose=0)
        if resp and ('IPerror' not in resp):
            # Response actually came from target, and not from IP stack (ICMP error dest/port unreachable)
            return True
        return False

    def ack_con(self, mid):
        if not TARGET_IPV6:
            return sr1(IP(dst=self.aut_host)/UDP(sport=self.aut_src_port, dport=self.aut_port)/CoAP(type=2, code=0, msg_id=mid), timeout=0.001, verbose=0)
        else:
            return sr1(IPv6(dst=self.aut_host)/UDP(sport=self.aut_src_port, dport=self.aut_port)/CoAP(type=2, code=0, msg_id=mid), timeout=0.001, verbose=0)

    def pre_send(self, model_tc, total_model_tc, option_tc, total_option_tc, total_tc, msg):
        if self.procmon:
            self.procmon.pre_send(self.current_tc)

        if self.current_tc % 10 == 0:
            self.overall_msg = "%s | Overall TC: %d/%d | Option TC: %d/%d | Model TC: %d/%d | Current Unanswered Packets: %d/%d" % (msg, self.current_tc, total_tc, option_tc, total_option_tc, model_tc, total_model_tc, len(self.current_unans), MAX_UNANS)
            self.log(self.overall_msg)

    def post_send(self, result, option_name, model_id, target_path=None, last_tc_from_model=False, smart_mutated_value=None):
        invalid_pkt_format = False

        if type(result) is tuple and ('IPerror' not in result[1]):
            # Packet was answered
            try:
                rendered_pkt = CoAP(result[0].load)
            except struct.error:
                rendered_pkt = result[0].load
                invalid_pkt_format = True
                self.invfile.write( "%s\t%s\t%d\t%s\t%d\t%s\n" %
                    (option_name, model_id, self.current_tc, result[0].load, len(result[0].load), "answered")
                )
                pass

            self.current_unans = []

            if result[1]['CoAP'].type == 0:
                #If CON, send ACK; so the server stop trying to resend, making the message matching more difficult
                self.ack_con(result[1]['CoAP'].msg_id)
        else:
            # Packet was NOT answered
            if type(result) is tuple:
                result = result[0]

            try:
                rendered_pkt = CoAP(result.load)
            except struct.error:
                rendered_pkt = result.load
                invalid_pkt_format = True
                self.invfile.write( "%s\t%s\t%d\t%s\t%d\t%s\n" %
                    (option_name, model_id, self.current_tc, result.load, len(result.load), "unanswered")
                )
                pass
            self.current_unans.append((self.current_tc, rendered_pkt))

        # Fill out self.last_sent
        # TODO: move out from the 'if not invalid_pkt_format'
        try:
            self.last_sent.append((self.current_tc, rendered_pkt))
        except KeyError:
            self.last_sent = deque([(self.current_tc, rendered_pkt)], maxlen=MAX_LAST_SENT)
            pass

        if not invalid_pkt_format:
            # Get target_path
            if (not target_path) and option_name == 'header' and model_id not in ['R', 'R-L']:
                path_pieces = []
                for opt in rendered_pkt.options:
                    if opt[0] == 'Uri-Path' or opt[0] == 11L or opt[0] == 11:
                        path_pieces.append(opt[1] if opt[1] is not None else '')
                target_path = '/'.join(path_pieces)

            # Fill out self.last_to_path
            if target_path is not None:
                try:
                    self.last_to_path[target_path].append((self.current_tc, rendered_pkt))
                except KeyError:
                    self.last_to_path[target_path] = deque([(self.current_tc, rendered_pkt)], maxlen=MAX_TO_PATH)
                    pass

            # Report the mutated value used on this TC
            if option_name in ['bits', 'bytes', 'field']:
                mutated_value = None
            elif option_name in ['string', 'opaque', 'uint', 'empty', 'payload']:
                mutated_value = smart_mutated_value
            else:
                mutated_value = self.get_mutated_value(option_name, model_id, rendered_pkt)
            if mutated_value:
                self.mutfile.write( "%s\t%s\t%d\t%s\n" %\
                    ( option_name, model_id, self.current_tc, mutated_value )
                )

        # Packet was NOT answered, check target's health
        if len(self.current_unans) > 0:
            if ( not self.poll_pedrpc() ) or ( len(self.current_unans) >= MAX_UNANS ) or last_tc_from_model:
                self.log("Sending Heartbeat...")
                if self.heartbeat():
                    # TODO: Erlang gen_coap hack; double-check to see if it's really dead
                    if "gen_coap" in self.name and self.heartbeat():
                        # Target still alive; finish this
                        self.current_unans = []
                    else:
                        # Target still alive; finish this
                        self.current_unans = []
                else:
                    # Target is dead, fill out reports
                    # File Failed Test Cases (FTC): keeps details of the TCs in which crashes were detected
                    self.ftcfile.write( "%s\t%s\t%s\t%d\n" %\
                        ( option_name, model_id,
                        target_path if target_path else '',
                        self.current_tc )
                    )

                    # File PCAP: keeps the last sent packets (max=MAX_LAST_SENT) and the last packets sent to
                    # the same URI/Resource (max=MAX_TO_PATH) as the TC in which the crash was detected
                    self.pcapfile.write("Crash detected on TC: %d\nCurrent Unanswered Packets: %d\n" %
                        ( self.current_tc, len(self.last_sent) )
                    )
                    # Save the last sent packets
                    for sent_pkt in self.last_sent:
                        self.pcapfile.write("TC: %d\n%s\n\n" % ( sent_pkt[0], hexdump(sent_pkt[1], dump=True) ))
                    # Save the last packets to the same URI/Resource; if target URI/Resource is known
                    if target_path is not None:
                        self.pcapfile.write("Last Packets sent to this Uri-Path (%s): %d\n" % (target_path, len(self.last_to_path[target_path])) )
                        for recent_pkt in self.last_to_path[target_path]:
                            self.pcapfile.write("TC: %d\n%s\n\n" % ( recent_pkt[0], hexdump(recent_pkt[1], dump=True) ))
                    self.pcapfile.write('\n')

                    self.current_unans = []
                    self.last_to_path = {}
                    self.last_sent = deque(maxlen=MAX_UNANS)
                    self.crash_count += 1
                    self.restart_target()

        self.current_tc += 1
