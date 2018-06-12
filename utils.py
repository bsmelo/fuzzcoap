from target_list import *
from scapy.all import *

# IPv6?
TARGET_IPV6 = False

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
