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

def get_target_info_list(target_name, aut_host, aut_port):
    # USER: user home directory
    USER_DIR = "/home/vagrant"
    # USER: base directory where the target applications are located
    BASE_DIR = "%s/coap-apps" % (USER_DIR)

    # USER: example of a user-defined list of strings to be used against a specific SUT.
    # This example contains relevant strings for Resource Directory targets, and is used against the txthings-rd SUT
    _rd_strings = [
        'rd', 'rd-lookup', 'd', 'ep', 'ep=', 'ep=cli','res', 'lt', 'et',
        'gp', 'con', 'page', 'count', 'resource-param',
    ]

    _target_list = {

        'aiocoap-server': {
            'start_cmd': "python3.5 %s/aiocoap/server.py" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'aiocoap',
        },

        'californium-plugtest': {
            'start_cmd': "java -jar %s/californium/demo-apps/cf-plugtest-server/target/cf-plugtest-server-1.1.0-SNAPSHOT.jar" % (BASE_DIR),
            'time_to_settle': 2,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'californium',
        },

        'canopus-server': {
            'start_cmd': "stdbuf -o 0 %s/go/src/github.com/zubairhamed/canopus/server" % (BASE_DIR),
            'env': {
                'GOPATH': "%s/go" % (BASE_DIR),
                'LD_LIBRARY_PATH': "%s/go/src/github.com/zubairhamed/canopus/openssl/" % (BASE_DIR),
            },
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'canopus',
        },

        'cantcoap-server': {
            'start_cmd': "%s/cantcoap/examples/plain/server %s %d" % (BASE_DIR, aut_host, aut_port),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', 'test')],
            'default_uris': ['test'],
            'lib': 'cantcoap',
        },

        'coapp-server': {
            'start_cmd': "stdbuf -o 0 %s/CoaPP/build-dir/server/src/coap_server" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', 'heartbeat')],
            'default_uris': ['name', 'dynamic', 'dynamic/?', 'observable'],
            'bin_file': '%s/CoaPP/build-dir/server/src/coap_server' % (BASE_DIR),
            'lib': 'CoAPP',
        },

        'coapthon-server': {
            'start_cmd': "python %s/CoAPthon/coapserver.py -i %s -p %d" % (BASE_DIR, aut_host, aut_port),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'CoAPthon',
        },

        'contiki-native-erbium-plugtest': {
            # USER: requires initial setup for tun/tap interfaces, radvd and IPv6
            # sudo sysctl -w net.ipv6.conf.all.forwarding=1 && sudo ip tuntap add tap0 mode tap user ${USER} && sudo ip link set tap0 up && sudo ip tuntap add tun0 mode tun user ${USER} && sudo ip link set tun0 up && sudo ip address add 2001:db8:1::a/64 dev tap0 && sudo ip address add fd00::1/64 dev tun0 && sudo service radvd restart
            'start_cmd': "stdbuf -o 0 %s/contiki-ng/examples/coap/coap-plugtest-server/coap-plugtest-server.native" % (BASE_DIR),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'bin_file': "%s/contiki-ng/examples/coap/coap-plugtest-server/coap-plugtest-server.native" % (BASE_DIR),
            'lib': 'erbium',
        },

        'freecoap-server': {
            'start_cmd': "stdbuf -o 0 %s/FreeCoAP/test/test_coap_server/test_coap_server" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', 'heartbeat')],
            'default_uris': ['/sep/uri/path', 'unsafe', 'block'],
            'lib': 'FreeCoAP',
        },

        'gen_coap-server': {
            'start_cmd': "%s/gen_coap/coap-server.sh" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'gen_coap',
        },

        'ibm-crosscoap-proxy': {
            # USER: requires initial setup for backend http server (on a separate window)
            # ./make_srvdir.sh && python http_server.py 8800 /tmp/srvfiles 2>&1 | tee campaign_path/http_server.log
            'start_cmd': "stdbuf -o 0 %s/go/bin/crosscoap -listen %s:%d -backend http://localhost:8800/ -accesslog /dev/stdout" % (BASE_DIR, aut_host, aut_port),
            'env': {
                'GOPATH': "%s/go" % (BASE_DIR),
                'GOROOT': "/usr/local/go",
                'PATH': "%s/bin" % "/usr/local/go",
            },
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': [''],
            # USER: suggestion to use valid target URIs. In this case, those created by make_srvdir.sh:
            # 'default_uris': ['', 'dir', 'dir/t', 'ct', '1', 'a'],
            'lib': 'go-coap',
        },

        'java-coap-server': {
            # USER: requires initial setup, setting the java version of the current shell to Java 8:
            # sdk use java 8.0.172-zulu
            'start_cmd': "java -jar %s/java-coap/example-server/target/example-server-5.1.0-SNAPSHOT-jar-with-dependencies.jar" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'java-coap',
        },

        'jcoap-plugtest': {
            'start_cmd': "java -Dlog4j.configurationFile=file:{bd}/jcoap/ws4d-jcoap-applications/src/log4j2.xml -cp {bd}/jcoap/ws4d-jcoap-plugtest/src/:{bd}/jcoap/ws4d-jcoap/target/dependency/:{bd}/jcoap/ws4d-jcoap/target/jcoap-core-1.1.5.jar:{ud}/.m2/repository/org/apache/logging/log4j/log4j-api/2.10.0/log4j-api-2.10.0.jar:{ud}/.m2/repository/org/apache/logging/log4j/log4j-core/2.10.0/log4j-core-2.10.0.jar:{ud}/.m2/repository/commons-cli/commons-cli/1.2/commons-cli-1.2.jar:{ud}/.m2/repository/commons-logging/commons-logging/1.1.1/commons-logging-1.1.1.jar:{ud}/.m2/repository/commons-logging/commons-logging-api/1.1/commons-logging-api-1.1.jar:{ud}/.m2/repository/commons-codec/commons-codec/1.6/commons-codec-1.6.jar:{ud}/.m2/repository/org/slf4j/slf4j-api/1.7.7/slf4j-api-1.7.7.jar org.ws4d.coap.test.PlugtestServer".format(bd=BASE_DIR, ud=USER_DIR),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'jcoap',
        },

        'libcoap-server': {
            'start_cmd': "%s/libcoap/examples/coap-server -A %s -p %d -v 9" % (BASE_DIR, aut_host, aut_port),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'bin_file': "%s/libcoap/examples/coap-server" % (BASE_DIR),
            'lib': 'libcoap',
        },

        'libnyoci-plugtest': {
            'start_cmd': "%s/libnyoci/src/plugtest/nyoci-plugtest-server %d" % (BASE_DIR, aut_port),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'bin_file': "%s/libnyoci/src/plugtest/nyoci-plugtest-server" % (BASE_DIR),
            'lib': 'libnyoci',
        },

        'mongoose-server': {
            'start_cmd': "stdbuf -o 0 %s/mongoose/examples/coap_server/coap_server" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', 'heartbeat')],
            'default_uris': [''],
            'bin_file': '%s/mongoose/examples/coap_server/coap_server' % (BASE_DIR),
            'lib': 'mongoose-coap',
        },

        'ncoap-server': {
            # USER: requires initial setup, setting the java version of the current shell to Java 8:
            # sdk use java 8.0.172-zulu
            'start_cmd': "java -jar %s/nCoAP/ncoap-simple-server/target/ncoap-simple-server-1.8.3-SNAPSHOT.one-jar.jar" % (BASE_DIR),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'nCoAP',
        },

        'node-coap-server': {
            'start_cmd': "node %s/node-coap/examples/server.js" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', 'heartbeat')],
            'default_uris': [''],
            'lib': 'node-coap',
        },

        'openwsn-server': {
            'start_cmd': "python %s/openwsn-coap/bin/server.py" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['test'],
            'lib': 'openwsn',
        },

        'riot-native-gcoap-server': {
            # USER: requires initial setup for tun/tap interfaces, radvd and IPv6
            # sudo sysctl -w net.ipv6.conf.all.forwarding=1 && sudo ip tuntap add tap0 mode tap user ${USER} && sudo ip link set tap0 up && sudo ip tuntap add tun0 mode tun user ${USER} && sudo ip link set tun0 up && sudo ip address add 2001:db8:1::a/64 dev tap0 && sudo ip address add fd00::1/64 dev tun0 && sudo service radvd restart
            'start_cmd': "stdbuf -o 0 %s/RIOT/examples/gcoap/bin/native/gcoap_example.elf tap0" % (BASE_DIR),
            'time_to_settle': 3.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'bin_file': "%s/RIOT/examples/gcoap-dbg/bin/native/gcoap_example.elf" % (BASE_DIR),
            'lib': 'gcoap',
        },

        'riot-native-microcoap-server': {
            # USER: requires initial setup for tun/tap interfaces, radvd and IPv6
            # sudo sysctl -w net.ipv6.conf.all.forwarding=1 && sudo ip tuntap add tap0 mode tap user ${USER} && sudo ip link set tap0 up && sudo ip tuntap add tun0 mode tun user ${USER} && sudo ip link set tun0 up && sudo ip address add 2001:db8:1::a/64 dev tap0 && sudo ip address add fd00::1/64 dev tun0 && sudo service radvd restart
            'start_cmd': "stdbuf -o 0 %s/RIOT/tests/pkg_microcoap/bin/native/tests_pkg_microcoap.elf tap0" % (BASE_DIR),
            'time_to_settle': 3.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'bin_file': "%s/RIOT/tests/pkg_microcoap-dbg/bin/native/tests_pkg_microcoap-dbg.elf" % (BASE_DIR),
            'lib': 'microcoap',
        },

        'riot-native-nanocoap-server': {
            # USER: requires initial setup for tun/tap interfaces, radvd and IPv6
            # sudo sysctl -w net.ipv6.conf.all.forwarding=1 && sudo ip tuntap add tap0 mode tap user ${USER} && sudo ip link set tap0 up && sudo ip tuntap add tun0 mode tun user ${USER} && sudo ip link set tun0 up && sudo ip address add 2001:db8:1::a/64 dev tap0 && sudo ip address add fd00::1/64 dev tun0 && sudo service radvd restart
            'start_cmd': "stdbuf -o 0 %s/RIOT/examples/nanocoap_server/bin/native/nanocoap_server.elf tap0" % (BASE_DIR),
            'time_to_settle': 3.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'bin_file': "%s/RIOT/examples/nanocoap_server-dbg/bin/native/nanocoap_server.elf" % (BASE_DIR),
            'lib': 'nanocoap',
        },

        'ruby-coap-server': {
            'start_cmd': "stdbuf -o 0 %s/david/bin/rackup %s/david/config.ru" % (BASE_DIR, BASE_DIR),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core', 'echo/accept', 'hello', 'value', 'block', 'code', 'time', 'cbor', 'json'],
            'lib': 'ruby-coap',
        },

        'soletta-coap-server': {
            'start_cmd': "%s/soletta/build/stage/samples/coap/coap-sample-server" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['a/light'],
            'lib': 'soletta',
        },

        'txthings-rd': {
            'start_cmd': "python %s/txThings/examples/rd.py" % (BASE_DIR),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['rd', 'rd-lookup'],
            'lib': 'txThings',
            'strings': _rd_strings,
        },

        'txthings-server': {
            'start_cmd': "python %s/txThings/examples/server.py" % (BASE_DIR),
            'time_to_settle': 1,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'txThings',
        },

        'yacoap-piggyback': {
            'start_cmd': "%s/YaCoAP/tests/piggyback" % (BASE_DIR),
            'time_to_settle': 0.5,
            'heartbeat_path': [('Uri-Path', '.well-known'), ('Uri-Path', 'core')],
            'default_uris': ['.well-known/core'],
            'lib': 'YaCoAP',
        },

    }

    return _target_list[target_name]