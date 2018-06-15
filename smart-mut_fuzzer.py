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

from utils import *
from coap_target import Target
from fuzzer_models import *

smart_mutated_value = None

##################################################################################################
# Mutation Classes
##################################################################################################

class SmartValues(VolatileValue):
    def __init__(self, pkt_list, mut_mode, target_uri):
        self.pkt_list = [(CoAP(pkt[0]), pkt[1]) for pkt in pkt_list]
        self.mut_mode = mut_mode
        self.target_uri = target_uri
        self._idx = -1
    def _mutate_options(self, pkt, opt_idx, new_val):
        global smart_mutated_value
        # Mutates the option at opt_idx to new_val
        orig_name = pkt.options[opt_idx][0]
        pkt.options = pkt.options[:opt_idx] + [(orig_name, new_val)] + pkt.options[(opt_idx+1):]
        smart_mutated_value = "%s\t%d" % (repr(["%s=%s" % (orig_name, str(new_val))]), len(new_val))
        # Changes msg_id and token as well, to avoid duplicate rejection
        pkt.msg_id = RandShort()
        pkt.token = RandBin(pkt.tkl)
    def _mutate_payload(self, pkt, new_val):
        global smart_mutated_value
        # Mutates the payload
        pkt.payload.load = new_val
        smart_mutated_value = "%s\t%d" % (repr(["%s=%s" % ('payload', str(new_val))]), len(new_val))
        # Changes msg_id and token as well, to avoid duplicate rejection
        pkt.msg_id = RandShort()
        pkt.token = RandBin(pkt.tkl)
    def _change_target(self, pkt):
        # Changes the target URI to a known one, randomly selected from the self.target_uri list
        new_options = []
        for opt in pkt.options:
            if opt[0] != 'Uri-Path':
                new_options.append(opt)
        pkt.options = new_options + list(RandEnumKeys(self.target_uri))
    def _fix(self, inc_idx=True):
        if inc_idx:
            self._idx += 1
        pkt, opt_idx = self.pkt_list[self._idx % len(self.pkt_list)]
        pkt.paymark='\xff'
        pkt.payload = Raw(load="=%s[%d]=" % (self.mut_mode, self._idx))
        return str(pkt)[:65503]
    def __str__(self):
        return str(self._fix())

class SmartStrings(SmartValues):
    def _fix(self, inc_idx=True):
        if inc_idx:
            self._idx += 1
        pkt, opt_idx = self.pkt_list[self._idx % len(self.pkt_list)]
        orig_name = pkt.options[opt_idx][0]
        orig_val = pkt.options[opt_idx][1]

        if orig_val is None:
            orig_val = ''

        if self.target_uri:
            mut_mode = self.mut_mode.split('_')[1]
        else:
            mut_mode = self.mut_mode.split('_')[0]

        if 'StrEmpty' == mut_mode:
            self._mutate_options(pkt, opt_idx, '')
        elif 'StrAddNonPrintable' == mut_mode:
            self._mutate_options(pkt, opt_idx, orig_val + chr(random.choice( range(0,32) + range(127,255) )))
        elif 'StrOverflow' == mut_mode:
            self._mutate_options(pkt, opt_idx, orig_val+'%'*(option_model[orig_name][3]-len(orig_val)+1))
        elif 'StrPredefined' == mut_mode:
            predef_val = self.mut_mode.split('_')[-1]
            self._mutate_options(pkt, opt_idx, (predef_val*random.randint(1, option_model[orig_name][3]))[:option_model[orig_name][3]] )

        if self.target_uri:
            self._change_target(pkt)
        return str(pkt)[:65503]

class SmartOpaques(SmartValues):
    def _fix(self, inc_idx=True):
        if inc_idx:
            self._idx += 1
        pkt, opt_idx = self.pkt_list[self._idx % len(self.pkt_list)]
        orig_name = pkt.options[opt_idx][0]
        orig_val = pkt.options[opt_idx][1]

        if orig_val is None:
            orig_val = ''

        if self.target_uri:
            mut_mode = self.mut_mode.split('_')[1]
        else:
            mut_mode = self.mut_mode.split('_')[0]

        if 'OpaqueEmpty' == mut_mode:
            self._mutate_options(pkt, opt_idx, '')
        elif 'OpaqueOverflow' == mut_mode:
            self._mutate_options(pkt, opt_idx, orig_val+'%'*(option_model[orig_name][3]-len(orig_val)+1))
        elif 'OpaquePredefined' == mut_mode:
            predef_val = self.mut_mode.split('_')[-1]
            self._mutate_options( pkt, opt_idx, (predef_val*random.randint(1, option_model[orig_name][3]))[:option_model[orig_name][3]] )

        if self.target_uri:
            self._change_target(pkt)
        return str(pkt)[:65503]

def uint2hex(uint):
    try:
        # Length between 0-4 bytes (received positive integer)
        return struct.pack('I', uint).rstrip('\x00')
    except struct.error:
        # Length of 8 bytes (received negative integer)
        return struct.pack('l', uint).rstrip('\x00')

def hex2uint(_hex):
    return struct.unpack('l', _hex.ljust(8, '\x00'))[0]

class SmartUints(SmartValues):
    def _fix(self, inc_idx=True):
        if inc_idx:
            self._idx += 1
        pkt, opt_idx = self.pkt_list[self._idx % len(self.pkt_list)]
        orig_name = pkt.options[opt_idx][0]
        orig_val = pkt.options[opt_idx][1]

        if orig_val is None:
            orig_val = 0
        else:
            orig_val = hex2uint(orig_val)

        if self.target_uri:
            mut_mode = self.mut_mode.split('_')[1]
        else:
            mut_mode = self.mut_mode.split('_')[0]

        if 'UintNull' == mut_mode:
            self._mutate_options(pkt, opt_idx, '')
        elif 'UintAbsoluteMinusOne' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(-1))
        elif 'UintAbsoluteOne' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(1))
        elif 'UintAbsoluteZero' == mut_mode:
            self._mutate_options(pkt, opt_idx, '\x00')
        elif 'UintAddOne' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(orig_val+1))
        elif 'UintSubtractOne' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(orig_val-1))
        elif 'UintMaxRange' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(option_model[orig_name][3]))
        elif 'UintMinRange' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(option_model[orig_name][2]))
        elif 'UintMaxRangePlusOne' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(option_model[orig_name][3]+1))

        if self.target_uri:
            self._change_target(pkt)
        return str(pkt)[:65503]

class SmartEmpties(SmartValues):
    def _fix(self, inc_idx=True):
        if inc_idx:
            self._idx += 1
        pkt, opt_idx = self.pkt_list[self._idx % len(self.pkt_list)]
        orig_name = pkt.options[opt_idx][0]
        orig_val = pkt.options[opt_idx][1]

        if orig_val is None:
            orig_val = ''

        if self.target_uri:
            mut_mode = self.mut_mode.split('_')[1]
        else:
            mut_mode = self.mut_mode.split('_')[0]

        if 'EmptyAbsoluteMinusOne' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(-1))
        elif 'EmptyAbsoluteOne' == mut_mode:
            self._mutate_options(pkt, opt_idx, uint2hex(1))
        elif 'EmptyAbsoluteZero' == mut_mode:
            self._mutate_options(pkt, opt_idx, '\x00')
        elif 'EmptyPredefined' == mut_mode:
            predef_val = self.mut_mode.split('_')[-1]
            self._mutate_options(pkt, opt_idx, predef_val)

        if self.target_uri:
            self._change_target(pkt)
        return str(pkt)[:65503]

class SmartPayloads(SmartValues):
    def _fix(self, inc_idx=True):
        if inc_idx:
            self._idx += 1
        pkt = self.pkt_list[self._idx % len(self.pkt_list)][0]
        try:
            orig_val = pkt.payload.load
        except AttributeError:
            orig_val = ''

        if self.target_uri:
            mut_mode = self.mut_mode.split('_')[1]
        else:
            mut_mode = self.mut_mode.split('_')[0]

        str_pkt = str(pkt)
        if 'PayloadEmpty' == mut_mode:
            self._mutate_payload(pkt, '')
        elif 'PayloadAddNonPrintable' == mut_mode:
            self._mutate_payload(pkt, orig_val + chr(random.choice( range(0,32) + range(127,255) )))
        elif 'PayloadPredefined' == mut_mode:
            predef_val = self.mut_mode.split('_')[-1]
            self._mutate_payload(pkt, (predef_val*random.randint(1, 65507 - (len(str_pkt) - len(orig_val))))[:65507 - (len(str_pkt) - len(orig_val))] )

        if self.target_uri:
            self._change_target(pkt)
        return str(pkt)[:65503]

class SmartFields(SmartValues):
    def _coap_option_to_null(self, pkt, opt_idx):
        ''' Changes the whole CoAP Option field at @opt_idx to null '''
        opt = pkt.options[opt_idx]
        l = pkt.options
        # Sort the list of options by option number
        l.sort( lambda x, y: cmp(option_model[x[0]][0], option_model[y[0]][0]) )
        # Replace options for the sorted one and grabs new opt_idx
        pkt.options = l
        opt_idx = pkt.options.index(opt)

        cur_delta = 0
        opt_total_len = []
        for opt in pkt.options:
            if (option_model[opt[0]][0] - cur_delta) < 13:
                delta_extended = 0
            elif (option_model[opt[0]][0] - cur_delta) < 269:
                delta_extended = 1
            else:
                delta_extended = 2
            cur_delta += (option_model[opt[0]][0] - cur_delta)

            try:
                opt_len = len(opt[1])
            except TypeError:
                # TypeError: object of type 'NoneType' has no len()
                opt_len = 0
            if opt_len < 13:
                len_extended = 0
            elif opt_len < 269:
                len_extended = 1
            else:
                len_extended = 2

            opt_total_len.append(1+delta_extended+len_extended+opt_len)

        opt_lidx = sum(opt_total_len[:opt_idx])
        opt_hidx = sum(opt_total_len[opt_idx+1:])
        new_pkt = str(pkt)[:4+pkt.tkl+opt_lidx] + '\x00'*opt_total_len[opt_idx] + str(pkt)[-(len(pkt.payload)+1+sum(opt_total_len[opt_idx+1:])):]

        return CoAP(new_pkt)

    def _coap_payload_to_null(self, pkt):
        ''' Changes the whole CoAP Payload field (+ paymark) to null '''
        pkt.paymark='\x00'
        pkt.payload.load = '\x00'*len(pkt.payload.load)
        return pkt
        #new_pkt = str(pkt)[:-(len(pkt.payload.load)+1)] + '\x00'*(len(pkt.payload.load)+1)
        #return CoAP(new_pkt)

    def _remove_option(self, pkt, opt_idx):
        l = pkt.options
        del l[opt_idx]
        pkt.options = l
        return pkt

    def _remove_payload(self, pkt):
        del pkt.payload
        del pkt.paymark
        return pkt

    def _duplicate_option(self, pkt, opt_idx):
        l = pkt.options
        l.append(l[opt_idx])
        pkt.options = l
        return pkt

    def _duplicate_payload(self, pkt):
        pkt.payload.load += '\xff' + pkt.payload.load
        return pkt

    def _fix(self, inc_idx=True):
        if inc_idx:
            self._idx += 1
        pkt, opt_idx = self.pkt_list[self._idx % len(self.pkt_list)]

        if self.target_uri:
            mut_mode = self.mut_mode.split('_')[1]
        else:
            mut_mode = self.mut_mode.split('_')[0]

        if 'FieldNull' == mut_mode:
            if opt_idx == -1:
                new_pkt = self._coap_payload_to_null(pkt)
            else:
                new_pkt = self._coap_option_to_null(pkt, opt_idx)
        elif 'FieldRemove' == mut_mode:
            if opt_idx == -1:
                new_pkt = self._remove_payload(pkt)
            else:
                new_pkt = self._remove_option(pkt, opt_idx)
        elif 'FieldDuplicate' == mut_mode:
            if opt_idx == -1:
                new_pkt = self._duplicate_payload(pkt)
            else:
                new_pkt = self._duplicate_option(pkt, opt_idx)

        if self.target_uri:
            self._change_target(new_pkt)
        return str(new_pkt)[:65503]

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

    def get_total_tc(self):
        tc_num = 0
        for target_name in self.fuzz_models.keys():
            for option_name in self.fuzz_models[target_name].keys():
                for model_id, model in self.fuzz_models[target_name][option_name].iteritems():
                    tc_num += model[1]

        return tc_num

    def print_table(self):
        models = []
        tcs = []
        for target_name in self.fuzz_models.keys():
            for o in self.info[target_name]['active_options']:
                tc_num = 0
                for k,v in self.fuzz_models[target_name][o].iteritems():
                    tc_num += v[1]
                models.append(len(self.fuzz_models[target_name][o]))
                tcs.append(tc_num)
            table_str = Table(
                Column( "Option Name",
                    [ o for o in self.info[target_name]['active_options'] ] + ["="*22, "Total"], align=ALIGN.LEFT ),
                Column( "Templates/Generators", models + ["="*22, sum(models)] ),
                Column( "Test Cases", tcs + ["="*22, sum(tcs)] ),
            )
            print table_str
            self.targets[target_name].summaryfile.write(str(table_str)+'\n\n\n')

##################################################################################################
# Fuzzer Object: Setup Functions
##################################################################################################

    def setup(self, target_name):
        self.info[target_name] = {}
        self.info[target_name]['total_active_models'] = 0
        self.info[target_name]['active_options'] = ['string', 'opaque', 'uint', 'empty', 'payload', 'field']

        self.targets[target_name].pedrpc_connect()
        self.targets[target_name].start_target()
        time.sleep(1)
        self.targets[target_name].init_known_paths()
        time.sleep(1)

        self.target_paths[target_name] = []
        kp_i = 0
        for kp in self.targets[target_name].known_paths:
            self.target_paths[target_name].append([])
            for segment in kp.split('/'):
                self.target_paths[target_name][kp_i].append((11L, segment))
            kp_i = kp_i + 1

        self.fuzz_models[target_name] = OrderedDict()
        self.fuzz_models[target_name]['string'] = OrderedDict()
        self.fuzz_models[target_name]['opaque'] = OrderedDict()
        self.fuzz_models[target_name]['uint'] = OrderedDict()
        self.fuzz_models[target_name]['empty'] = OrderedDict()
        self.fuzz_models[target_name]['payload'] = OrderedDict()
        self.fuzz_models[target_name]['field'] = OrderedDict()

        pcap_pkts = rdpcap("conversation.pcapng")

        origin_pkts = {'string': [], 'opaque': [], 'uint': [], 'empty': [], 'payload': [], 'field': []}
        for pkt in pcap_pkts:
            if pkt.dport == 5683:
                for opt in pkt['CoAP'].options:
                    origin_pkts[ option_model[opt[0]][1] ].append( (str(pkt['CoAP']), pkt['CoAP'].options.index(opt)) )
                    origin_pkts['field'].append( (str(pkt['CoAP']), pkt['CoAP'].options.index(opt)) )
                if pkt['CoAP'].payload:
                    origin_pkts['payload'].append( (str(pkt['CoAP']), -1) )
                    origin_pkts['field'].append( (str(pkt['CoAP']), -1) )

        for prefix in ['', 'RandKTarget_']:
            if len(origin_pkts['string']) > 0:
                for mut_mode in [prefix + mode for mode in ['StrEmpty', 'StrAddNonPrintable', 'StrOverflow']]:
                    self.fuzz_models[target_name]['string'][mut_mode] = [SmartStrings(origin_pkts['string'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['string'])]
                for mut_mode in [prefix + mode for mode in ['StrPredefined_\x00', 'StrPredefined_8', 'StrPredefined_#', 'StrPredefined_😍', 'StrPredefined_%']]:
                    self.fuzz_models[target_name]['string'][mut_mode] = [SmartStrings(origin_pkts['string'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['string'])]
            else:
                self.fuzz_models[target_name].pop('string', None)

            if len(origin_pkts['opaque']) > 0:
                for mut_mode in [prefix + mode for mode in ['OpaqueEmpty', 'OpaqueOverflow']]:
                    self.fuzz_models[target_name]['opaque'][mut_mode] = [SmartOpaques(origin_pkts['opaque'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['opaque'])]
                for mut_mode in [prefix + mode for mode in ['OpaquePredefined_\x00', 'OpaquePredefined_\xff', 'OpaquePredefined_😍', 'OpaquePredefined_%']]:
                    self.fuzz_models[target_name]['opaque'][mut_mode] = [SmartOpaques(origin_pkts['opaque'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['opaque'])]
            else:
                self.fuzz_models[target_name].pop('opaque', None)

            if len(origin_pkts['uint']) > 0:
                for mut_mode in [prefix + mode for mode in ['UintNull', 'UintAbsoluteMinusOne', 'UintAbsoluteOne', 'UintAbsoluteZero', 'UintAddOne', 'UintSubtractOne', 'UintMaxRange', 'UintMinRange', 'UintMaxRangePlusOne']]:
                    self.fuzz_models[target_name]['uint'][mut_mode] = [SmartUints(origin_pkts['uint'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['uint'])]
            else:
                self.fuzz_models[target_name].pop('uint', None)

            if len(origin_pkts['empty']) > 0:
                for mut_mode in [prefix + mode for mode in ['EmptyAbsoluteMinusOne', 'EmptyAbsoluteOne', 'EmptyAbsoluteZero']]:
                    self.fuzz_models[target_name]['empty'][mut_mode] = [SmartEmpties(origin_pkts['empty'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['empty'])]
                for mut_mode in [prefix + mode for mode in ['EmptyPredefined_\xff', 'EmptyPredefined_#', 'EmptyPredefined_😍', 'EmptyPredefined_%']]:
                    self.fuzz_models[target_name]['empty'][mut_mode] = [SmartEmpties(origin_pkts['empty'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['empty'])]
            else:
                self.fuzz_models[target_name].pop('empty', None)

            if len(origin_pkts['payload']) > 0:
                for mut_mode in [prefix + mode for mode in ['PayloadEmpty', 'PayloadAddNonPrintable']]:
                    self.fuzz_models[target_name]['payload'][mut_mode] = [SmartPayloads(origin_pkts['payload'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['payload'])]
                for mut_mode in [prefix + mode for mode in ['PayloadPredefined_\x00', 'PayloadPredefined_\xff', 'PayloadPredefined_#', 'PayloadPredefined_😍', 'PayloadPredefined_%']]:
                    self.fuzz_models[target_name]['payload'][mut_mode] = [SmartPayloads(origin_pkts['payload'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['payload'])]
            else:
                self.fuzz_models[target_name].pop('payload', None)

            if len(origin_pkts['field']) > 0:
                for mut_mode in [prefix + mode for mode in ['FieldNull', 'FieldRemove', 'FieldDuplicate']]:
                    self.fuzz_models[target_name]['field'][mut_mode] = [SmartFields(origin_pkts['field'], mut_mode, self.target_paths[target_name] if prefix else None), len(origin_pkts['field'])]
            else:
                self.fuzz_models[target_name].pop('field', None)

        active_models = 0
        for opt_type in self.fuzz_models[target_name]:
            active_models += len(opt_type)

        self.info[target_name]['total_active_models'] += active_models

        self.total_tc = self.get_total_tc()

        self.print_table()

##################################################################################################
# Fuzzer Object: Running Functions
##################################################################################################

    def run_model(self, target_name, option_name, model_id, opt_tc, msg, target_path=None):
        global smart_mutated_value
        start = time.time()
        total_model_tc = self.fuzz_models[target_name][option_name][model_id][1]

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
                ans, unans = sr(IP(dst=self.targets[target_name].aut_host)/UDP(sport=self.targets[target_name].aut_src_port, dport=self.targets[target_name].aut_port)/str(self.fuzz_models[target_name][option_name][model_id][0])[:65507], verbose=0, timeout=REQUEST_TIMEOUT)
            else:
                ans, unans = sr(IPv6(dst=self.targets[target_name].aut_host)/UDP(sport=self.targets[target_name].aut_src_port, dport=self.targets[target_name].aut_port)/str(self.fuzz_models[target_name][option_name][model_id][0])[:1452], verbose=0, timeout=REQUEST_TIMEOUT)
            time.sleep(INTERVAL_BETWEEN_REQUESTS)
            self.targets[target_name].post_send(ans[0] if ans else unans[0], option_name, model_id, target_path, (count+1) == total_model_tc, smart_mutated_value)
            smart_mutated_value = None
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

    def run_option(self, target_name, option_name):
        start = time.time()

        opt_tc = 1
        self.total_opt_tc = 0
        for model_id, model in self.fuzz_models[target_name][option_name].iteritems():
            self.total_opt_tc += model[1]

        initial_opt_crash_count = self.targets[target_name].crash_count
        for model_id, model in self.fuzz_models[target_name][option_name].iteritems():
            target_path = None
            msg = "Fuzzing %s | Model ID: %s" %\
                ('Header' if option_name == 'header' else 'Option: %s' % option_name,
                model_id)
            if option_name != 'header' and ("KU" in model_id):
                target_path = (self.targets[target_name].known_paths[ int(model_id.split('_')[-1]) ])
                msg += " | Target Resource: %s" % target_path

            opt_tc = self.run_model(target_name, option_name, model_id, opt_tc, msg, target_path)


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

    def run(self):
        for target_name in self.fuzz_models.keys():
            start = time.time()
            first_option = True
            for option_name in self.fuzz_models[target_name].keys():
                if not first_option:
                    self.targets[target_name].restart_target()
                    first_option = False
                self.run_option(target_name, option_name)
            time_msg = "Total Time: %.5fs" % (time.time() - start)
            print time_msg
            self.targets[target_name].summaryfile.write(time_msg)

            self.targets[target_name].stop_target()

##################################################################################################
# Main
##################################################################################################

USAGE = "USAGE: smart-mut_fuzzer.py"\
        "\n    [-t|--target_name tname]         Application/System Under Test's Identifier " \
        "\n                                     (from target_list.py)" \
        "\n    [-h|--host ipv4]                 Process Monitor's Host" \
        "\n    [-p|--port port]                 Process Monitor's TCP port"\
        "\n    [-H|--aut_host aut_ipv4]         Application/System Under Test's Host" \
        "\n    [-P|--aut_port aut_port]         Application/System Under Test's UDP port (CoAP dst)"\
        "\n    [-c|--aut_src_port aut_src_port] CoAP source port (CoAP src)"\
        "\n    -d|--output_dir dir              directory where output files are put "\
        "\n                                     (as in 'output/<target_name>')"

ERR   = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)

if __name__ == "__main__":
    # parse command line options.
    opts = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:h:p:H:P:c:d:",
            ["target_name=", "host=", "port=", "aut_host=", "aut_port=", "aut_src_port=", "output_dir="] )
    except getopt.GetoptError:
        ERR(USAGE)

    target_name = None
    host = None
    port = None
    aut_host = None
    aut_port = None
    aut_src_port = None
    coredump_dir = None
    for opt, arg in opts:
        if opt in ("-t", "--target_name"):
            target_name  = arg
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

    if not output_dir or not target_name:
        ERR(USAGE)

    if not os.path.isdir(output_dir):
        ERR("output_dir must be an existing directory")

    if not host or host == "-1":
        host = PROCMON_DEFAULT_DST_HOST

    if not port or port == -1:
        port = PROCMON_DEFAULT_DST_PORT

    if not aut_host or aut_host == "-1":
        aut_host = COAP_AUT_DEFAULT_DST_HOST 

    if not aut_port or aut_port == -1:
        aut_port = COAP_AUT_DEFAULT_DST_PORT

    if not aut_src_port or aut_src_port == -1:
        aut_src_port = COAP_AUT_DEFAULT_SRC_PORT

    my_seed = ord(os.urandom(1))
    random.seed(my_seed)
    print "Using %d as seed" % my_seed

    # Retrieve SUT-specific configuration from target_list.py
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
        output_dir=output_dir
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
    mf.run()
