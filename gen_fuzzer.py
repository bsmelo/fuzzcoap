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

    def setup_model(self, target_name, option_name, nmi, nmo, tc_num=None):
        # nmi: new_model_id; nmo: new_model_options
        self.fuzz_models[target_name][option_name][nmi] = [copy.deepcopy(self.fuzz_models[target_name]['header'][nmi.split('_')[1]][0]), tc_num if tc_num else K_GEN]
        self.fuzz_models[target_name][option_name][nmi][0].options = nmo

    def setup_opaque_or_string_option(self, target_name, option_type, option_name, min_len, max_len, rand_class, rand_sing_class, seq_sing_class, special_classes, opt_ext_list):
        self.fuzz_models[target_name][option_name] = OrderedDict()
        # Option + Random Options (and possibly Random Payload)
        self.setup_model(target_name, option_name, 'O_R-L',
            [(option_name, rand_class(RandNum(min_len, max_len)))]
        )

        # Option-Only + Empty Payload (sent to Empty Uri)
        self.setup_model(target_name, option_name, 'O_EP-L_EU',
            RandEnumKeys([[(option_name, rand_class(i))] for i in xrange(min_len, max_len+1)])
        )

        # Option-Only + Random Payload (sent to a Empty Uri)
        self.setup_model(target_name, option_name, 'O_RP-L_EU',
            RandEnumKeys([[(option_name, rand_class(i))] for i in xrange(min_len, max_len+1)])
        )

        for tp_i in xrange(0, len(self.target_paths[target_name])):
            # Option-Only + Empty Payload (sent to a Known Uri)
            self.setup_model(target_name, option_name, 'O_EP-L_KU_'+str(tp_i),
                RandEnumKeys([self.target_paths[target_name][tp_i] +
                    [(option_name, rand_class(i))] for i in xrange(min_len, max_len+1)
                ])
            )

        for tp_i in xrange(0, len(self.target_paths[target_name])):
            # Option-Only + Random Payload (sent to a Known Uri)
            self.setup_model(target_name, option_name, 'O_RP-L_KU_'+str(tp_i),
                RandEnumKeys([self.target_paths[target_name][tp_i] +
                    [(option_name, rand_class(i))] for i in xrange(min_len, max_len+1)
                ])
            )

        ext_list = opt_ext_list + self.targets[target_name].opt_ext_list[ option_model[option_name][1] ]
        rand_sing_tc_num = 0
        seq_sing_tc_num = 0
        for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice:
            rand_sing_tc_num += len(rand_sing_class(i, ext_list=ext_list)._choice) # K_O_FORMAT (string) = 3601 [1--255] or 3751 [0--255] or 5401 [1--1034]
            seq_sing_tc_num += len(seq_sing_class(i, ext_list=ext_list)._choice # K_O_FORMAT (opaque) = 604
            )

        if GEN_ALL or option_type == 'string':
            # Random special with all special sizes based upon Option-Only + Empty Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_EP-L_KU_rs_'+str(tp_i),
                    RandEnumKeys([self.target_paths[target_name][tp_i] +
                        [(option_name, rand_sing_class(i, ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                    ]),
                    tc_num=rand_sing_tc_num
                )

            # Random special with all special sizes based upon Option-Only + Random Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_RP-L_KU_rs_'+str(tp_i),
                    RandEnumKeys([self.target_paths[target_name][tp_i] +
                        [(option_name, rand_sing_class(i, ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                    ]),
                    tc_num=rand_sing_tc_num
                )

        if GEN_ALL or option_type == 'opaque':
            # All special with all special sizes based upon Option-Only + Empty Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_EP-L_KU_ss_'+str(tp_i),
                    RandEnumKeys([self.target_paths[target_name][tp_i] +
                        [(option_name, seq_sing_class(i, ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                    ]),
                    tc_num=seq_sing_tc_num
                )

            # All special with all special sizes based upon Option-Only + Random Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_RP-L_KU_ss_'+str(tp_i),
                    RandEnumKeys([self.target_paths[target_name][tp_i] +
                        [(option_name, seq_sing_class(i, ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                    ]),
                    tc_num=seq_sing_tc_num
                )

        if len(special_classes) == 2:
            query_attr_gen_classes = special_classes

            rand_class = getattr(scapy.all, 'RandPrefixString')
            rand_sing_class = getattr(scapy.all, 'RandSingPrefixString')
            if GEN_ALL:
                seq_sing_class = getattr(scapy.all, 'SeqSingPrefixString')

            if GEN_ALL:
                n_prefixes = len(query_attr_gen_classes)
            else:
                n_prefixes = 1
            for gen_class_i in xrange(0, n_prefixes):
                if gen_class_i == 0:
                    prefix_id = 'rs'
                else:
                    prefix_id = 'ss'

                rand_tc_num = 0
                rand_sing_tc_num = 0
                if GEN_ALL:
                    seq_sing_tc_num = 0
                for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice:
                    rand_tc_num += K_GEN # K_O_OPT_R (Uri-Query and Location-Query's QueryStrRandom) = 26 * 50 = 1300
                    rand_sing_tc_num += len(rand_sing_class(i, query_attr_gen_classes[gen_class_i](), ext_list=ext_list)._choice) # K_O_OPT_S (string) = 3751
                    if GEN_ALL:
                        seq_sing_tc_num += len(seq_sing_class(i, query_attr_gen_classes[gen_class_i](), ext_list=ext_list)._choice) # K_O_OPT_S (opaque)

                # Very Random very special with all special sizes based upon Option-Only + Empty Payload (sent to a Known Uri)
                for tp_i in xrange(0, len(self.target_paths[target_name])):
                    self.setup_model(target_name, option_name, 'O_EP-L_KU_P'+prefix_id+'Srr_'+str(tp_i),
                        RandEnumKeys([self.target_paths[target_name][tp_i] +
                            [(option_name, rand_class(i, query_attr_gen_classes[gen_class_i]()))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                        ]),
                        tc_num=rand_tc_num
                    )

                # Very Random very special with all special sizes based upon Option-Only + Random Payload (sent to a Known Uri)
                for tp_i in xrange(0, len(self.target_paths[target_name])):
                    self.setup_model(target_name, option_name, 'O_RP-L_KU_P'+prefix_id+'Srr_'+str(tp_i),
                        RandEnumKeys([self.target_paths[target_name][tp_i] +
                            [(option_name, rand_class(i, query_attr_gen_classes[gen_class_i]()))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                        ]),
                        tc_num=rand_tc_num
                    )

                # Random very special with all special sizes based upon Option-Only + Empty Payload (sent to a Known Uri)
                for tp_i in xrange(0, len(self.target_paths[target_name])):
                    self.setup_model(target_name, option_name, 'O_EP-L_KU_P'+prefix_id+'Srs_'+str(tp_i),
                        RandEnumKeys([self.target_paths[target_name][tp_i] +
                            [(option_name, rand_sing_class(i, query_attr_gen_classes[gen_class_i](), ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                        ]),
                        tc_num=rand_sing_tc_num
                    )

                # Random very special with all special sizes based upon Option-Only + Random Payload (sent to a Known Uri)
                for tp_i in xrange(0, len(self.target_paths[target_name])):
                    self.setup_model(target_name, option_name, 'O_RP-L_KU_P'+prefix_id+'Srs_'+str(tp_i),
                        RandEnumKeys([self.target_paths[target_name][tp_i] +
                            [(option_name, rand_sing_class(i, query_attr_gen_classes[gen_class_i](), ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                        ]),
                        tc_num=rand_sing_tc_num
                    )

                if GEN_ALL:
                    # All very special with all special sizes based upon Option-Only + Empty Payload (sent to a Known Uri)
                    for tp_i in xrange(0, len(self.target_paths[target_name])):
                        self.setup_model(target_name, option_name, 'O_EP-L_KU_P'+prefix_id+'Sss_'+str(tp_i),
                            RandEnumKeys([self.target_paths[target_name][tp_i] +
                                [(option_name, seq_sing_class(i, query_attr_gen_classes[gen_class_i](), ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                            ]),
                            tc_num=seq_sing_tc_num
                        )

                    # All very special with all special sizes based upon Option-Only + Random Payload (sent to a Known Uri)
                    for tp_i in xrange(0, len(self.target_paths[target_name])):
                        self.setup_model(target_name, option_name, 'O_RP-L_KU_P'+prefix_id+'Sss_'+str(tp_i),
                            RandEnumKeys([self.target_paths[target_name][tp_i] +
                                [(option_name, seq_sing_class(i, query_attr_gen_classes[gen_class_i](), ext_list=ext_list))] for i in SeqSingNum(min_len, max_len, neg=False, ext_list=[4096])._choice
                            ]),
                            tc_num=seq_sing_tc_num
                        )

        self.info[target_name]['total_active_models'] += len(self.fuzz_models[target_name][option_name])

    def setup_uint_or_empty_option(self, target_name, option_type, option_name, min_len, max_len, rand_class, rand_sing_class, seq_sing_class, special_classes, opt_ext_list):
        self.fuzz_models[target_name][option_name] = OrderedDict()
        # Option + Random Options (and possibly Random Payload)
        self.setup_model(target_name, option_name, 'O_R-L',
            [(option_name, rand_class(min_len, max_len))]
        )

        # Option-Only + Empty Payload (sent to Empty Uri)
        self.setup_model(target_name, option_name, 'O_EP-L_EU',
            [(option_name, rand_class(min_len, max_len))]
        )

        # Option-Only + Random Payload (sent to a Empty Uri)
        self.setup_model(target_name, option_name, 'O_RP-L_EU',
            [(option_name, rand_class(min_len, max_len))]
        )

        for tp_i in xrange(0, len(self.target_paths[target_name])):
            # Option-Only + Empty Payload (sent to a Known Uri)
            self.setup_model(target_name, option_name, 'O_EP-L_KU_'+str(tp_i),
                self.target_paths[target_name][tp_i] +
                    [(option_name, rand_class(min_len, max_len))]
            )

        for tp_i in xrange(0, len(self.target_paths[target_name])):
            # Option-Only + Random Payload (sent to a Known Uri)
            self.setup_model(target_name, option_name, 'O_RP-L_KU_'+str(tp_i),
                self.target_paths[target_name][tp_i] +
                    [(option_name, rand_class(min_len, max_len))]
            )

        if GEN_ALL:
            # Random special uint based upon Option-Only + Empty Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_EP-L_KU_rs_'+str(tp_i),
                    self.target_paths[target_name][tp_i] +
                        [(option_name, rand_sing_class(min_len, max_len))],
                    tc_num=len(rand_sing_class(min_len, max_len)._choice)
                )

            # Random special uint based upon Option-Only + Random Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_RP-L_KU_rs_'+str(tp_i),
                    self.target_paths[target_name][tp_i] +
                        [(option_name, rand_sing_class(min_len, max_len))],
                    tc_num=len(rand_sing_class(min_len, max_len)._choice)
                )

        # All special uint based upon Option-Only + Empty Payload (sent to a Known Uri)
        for tp_i in xrange(0, len(self.target_paths[target_name])):
            self.setup_model(target_name, option_name, 'O_EP-L_KU_ss_'+str(tp_i),
                self.target_paths[target_name][tp_i] +
                    [(option_name, seq_sing_class(min_len, max_len, ext_list=opt_ext_list))],
                tc_num=len(rand_sing_class(min_len, max_len)._choice) + (len(rand_sing_class(min_len, max_len)._choice)/3) + len(opt_ext_list) + 1 # K_O_FORMAT (uint/empty) = 4 [0--1] or 97 [0--2**24-1] or 65 [0--2**16-1] or 129 [0--2**32-1] (accounting for negative MAX_LEN generation)
            )

        # All special uint based upon Option-Only + Random Payload (sent to a Known Uri)
        for tp_i in xrange(0, len(self.target_paths[target_name])):
            self.setup_model(target_name, option_name, 'O_RP-L_KU_ss_'+str(tp_i),
                self.target_paths[target_name][tp_i] +
                    [(option_name, seq_sing_class(min_len, max_len, ext_list=opt_ext_list))],
                tc_num=len(rand_sing_class(min_len, max_len)._choice) + (len(rand_sing_class(min_len, max_len)._choice)/3) + len(opt_ext_list) + 1 # Account for negative MAX_LEN generation
            )

        if len(special_classes) == 2:
            special_rand_sing_class = special_classes[0]
            special_seq_sing_class = special_classes[1]

            # Perform twice the iterations for these specific options, to guarantee all Singular values are used at least once
            if option_name in ["Uri-Port", "Content-Format", "Accept"]:
                TC_BOMB = 2
            else:
                TC_BOMB = 1

            if GEN_ALL:
                # Random very special uint based upon Option-Only + Empty Payload (sent to a Known Uri)
                for tp_i in xrange(0, len(self.target_paths[target_name])):
                    self.setup_model(target_name, option_name, 'O_EP-L_KU_Frs_'+str(tp_i),
                        self.target_paths[target_name][tp_i] +
                            [(option_name, special_rand_sing_class())],
                        tc_num=len(special_rand_sing_class()._choice)
                    )

                # Random very special uint based upon Option-Only + Random Payload (sent to a Known Uri)
                for tp_i in xrange(0, len(self.target_paths[target_name])):
                    self.setup_model(target_name, option_name, 'O_RP-L_KU_Frs_'+str(tp_i),
                        self.target_paths[target_name][tp_i] +
                            [(option_name, special_rand_sing_class())],
                        tc_num=len(special_rand_sing_class()._choice)
                    )

            # All very special uint based upon Option-Only + Empty Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_EP-L_KU_Fss_'+str(tp_i),
                    self.target_paths[target_name][tp_i] +
                        [(option_name, special_seq_sing_class(ext_list=opt_ext_list))],
                    tc_num=len(special_seq_sing_class(ext_list=opt_ext_list)._choice) * TC_BOMB # K_O_OPT_S (uint) = 72 (Uri-Port) or 14 (Content-Format, Accept) or 976 (Block1, Block2)
                )

            # All very special uint based upon Option-Only + Random Payload (sent to a Known Uri)
            for tp_i in xrange(0, len(self.target_paths[target_name])):
                self.setup_model(target_name, option_name, 'O_RP-L_KU_Fss_'+str(tp_i),
                    self.target_paths[target_name][tp_i] +
                        [(option_name, special_seq_sing_class(ext_list=opt_ext_list))],
                    tc_num=len(special_seq_sing_class(ext_list=opt_ext_list)._choice) * TC_BOMB # K_O_OPT_S (uint) = 720 (Uri-Port) or 140 (Content-Format, Accept) or 976 (Block1, Block2)
                )

        self.info[target_name]['total_active_models'] += len(self.fuzz_models[target_name][option_name])

    def setup_option(self, target_name, option_name):
        self.fuzz_models[target_name][option_name] = []

        option_type = option_model[option_name][1]
        min_len = option_model[option_name][2]
        max_len = option_model[option_name][3]
        rand_class = option_type_model[option_type][0]
        rand_sing_class = option_type_model[option_type][1]
        seq_sing_class = option_type_model[option_type][2]
        special_classes = option_model[option_name][4]
        opt_ext_list = option_model[option_name][5]

        if option_type in ['opaque', 'string']:
            self.setup_opaque_or_string_option(target_name, option_type, option_name, min_len, max_len, rand_class, rand_sing_class, seq_sing_class, special_classes, opt_ext_list)
        elif option_type in ['uint', 'empty']:
            self.setup_uint_or_empty_option(target_name, option_type, option_name, min_len, max_len, rand_class, rand_sing_class, seq_sing_class, special_classes, opt_ext_list)

    def setup(self, target_name):
        self.info[target_name] = {}
        self.info[target_name]['total_active_models'] = 0
        self.info[target_name]['active_options'] = ['header', 'If-Match', 'Uri-Host',
            'ETag', 'If-None-Match', 'Observe', 'Uri-Port', 'Location-Path', 'Uri-Path',
            'Content-Format', 'Max-Age', 'Uri-Query', 'Accept', 'Location-Query', 'Block2',
            'Block1', 'Size2', 'Proxy-Uri', 'Proxy-Scheme', 'Size1']

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

        # 'R': Random Options (and possibly Random Payload)
        # 'EP': Empty Payload (sent to a Known Uri)
        # 'RP': Random Payload (sent to a Known Uri)
        self.fuzz_models[target_name] = OrderedDict()
        self.fuzz_models[target_name]['header'] = OrderedDict()

        # ---> Correct Version (1)
        # ---> Method Codes [GET, POST, PUT, DELETE] for Requests
        # ---> Message Types [CON, NON] for Requests and Sane Token (0..8 bytes)
        # R-L generate weird packets fuzzing all fields (including options), not directed at any specific path
        # All Random - Untargetted
        self.fuzz_models[target_name]['header']['R-L'] = [fuzz(CoAP(ver=1L, type=RandNum(0, 1), code=RandNum(1, 4), token=RandBin(RandNum(0, 8)), options=[]))/
            Raw(load=RandEnumKeys([ RandSingString(i) for i in SeqSingNum(0, 2**16-1 - 4096, neg=False, overflow_max=False)._choice ])), K_ALL_GEN]
        # EP-L fuzzes all fields but is directed to the known paths
        # Empty Payload - Targeted
        self.fuzz_models[target_name]['header']['EP-L'] = [fuzz(CoAP(ver=1L, type=RandNum(0, 1), code=RandNum(1, 4), token=RandBin(RandNum(0, 8)), options=RandEnumKeys(self.target_paths[target_name]), paymark=''))/
            Raw(load=RandEnumKeys([ RandSingString(i) for i in SeqSingNum(0, 2**16-1 - 4096, neg=False, overflow_max=False)._choice ])), K_ALL_GEN]
        # RP-L fuzzes all fields, directed to the known paths, but ensures a payload is present
        # Random Payload - Targeted
        self.fuzz_models[target_name]['header']['RP-L'] = [fuzz(CoAP(ver=1L, type=RandNum(0, 1), code=RandNum(1, 4), token=RandBin(RandNum(0, 8)), options=RandEnumKeys(self.target_paths[target_name]), paymark='\xff'))/
            Raw(load=RandEnumKeys([ RandSingString(i) for i in SeqSingNum(0, 2**16-1 - 4096, neg=False, overflow_max=False)._choice ])), K_ALL_GEN]
            # Special cases for Message ID and Token ID, the only rather large fields at the header, thus deserving this special treatment
        self.fuzz_models[target_name]['header']['MID'] = [fuzz(CoAP(ver=1L, type=RandNum(0, 1), code=RandNum(1, 4), token=RandBin(RandNum(0, 8)), msg_id=SeqSingNum(0, 2**16-1, neg=False, overflow_max=False), options=RandEnumKeys(self.target_paths[target_name]), paymark='\xff')/Raw()), len(SeqSingNum(0, 2**16-1, neg=False)._choice)] # 49 Singular Values
        self.fuzz_models[target_name]['header']['TKN'] = [fuzz(CoAP(ver=1L, type=RandNum(0, 1), code=RandNum(1, 4), token=RandEnumKeys([ SeqSingBin(i) for i in SeqSingNum(0, 8, neg=False)._choice ]), options=RandEnumKeys(self.target_paths[target_name]), paymark='\xff')/Raw()), len(SeqSingBin(1)._choice) * len(SeqSingNum(0, 8, neg=False)._choice)] # 603 Singular Values

        self.info[target_name]['total_active_models'] += len(self.fuzz_models[target_name]['header'])

        for option_name in self.info[target_name]['active_options']:
            if option_name != 'header':
                self.setup_option(target_name, option_name)

        self.total_tc = self.get_total_tc()

        self.print_table()


##################################################################################################
# Fuzzer Object: Running Functions
##################################################################################################

    def run_model(self, target_name, option_name, model_id, opt_tc, msg, target_path=None):
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

USAGE = "USAGE: gen_fuzzer.py"\
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
