# fuzzcoap
FuzzCoAP is ...TODO description.

## Installation
First of all, clone this repository:
```sh
$ git clone https://github.com/bsmelo/fuzzcoap
```

### Dependencies
[CoAPthon](https://github.com/Tanganelli/CoAPthon), to perform consistent `GET .well-known/core`:
```sh
$ git clone https://github.com/Tanganelli/CoAPthon.git
$ cd CoAPthon
$ python setup.py sdist
$ sudo pip install dist/CoAPthon-4.0.2.tar.gz -r requirements.txt
```
[boofuzz](https://github.com/jtpereyda/boofuzz), from which we borrow the `process_monitor_unix.py`:
```sh
$ git clone https://github.com/jtpereyda/boofuzz
$ cd boofuzz/
# Switch to a known-to-work version
$ git checkout 681ba34853658d9c08e1d34883b8bec46d68a848
$ sudo pip install .
```
[Scapy](https://github.com/secdev/scapy/), which we use to manipulate (and fuzz!) \[CoAP\] packets, as well as send/receive them:
```sh
$ git clone https://github.com/secdev/scapy/
$ cd scapy/
# Switch to a known-to-work version
$ git checkout 6db9cf9fb9d4b7aa148975373b185ab6da2afcf9
# Copy and apply relevant patches (of course the first argument here needs to be changed accordingly)
$ cp ~/fuzzcoap/001-Scapy-for-CoAP-and-Additional-Volatiles-for-Fuzzing.patch .
$ git apply 001-Scapy-for-CoAP-and-Additional-Volatiles-for-Fuzzing.patch
$ sudo python setup.py install
```

You should be good to go.

## Using FuzzCoAP
### Fuzzing
In this example we will fuzz the demo server provided with the [cantcoap](https://github.com/staropram/cantcoap) library.

1. Set `USER_DIR` and `BASE_DIR` in the [target_list.py](target_list.py) file. Specific configuration for the target application can be checked in the same file as well.

2. Start the Process Monitor (the script also creates an output folder for this Fuzzing Campaign, enables coredump files and so on):
```sh
$ ./target_random.sh cantcoap-server
```

Using `$ less out_r/cantcoap-server/1/target.log`, the output below should be seen:
```
[22:05.23] Process Monitor PED-RPC server initialized:
[22:05.23] Listening on 127.0.0.1:35111
[22:05.23] awaiting requests...
```

3. Start the Fuzzer script:
```sh
$ ./fuzz_random.sh cantcoap-server
```

4. Run the Fuzzing Campaign:
```python
Welcome to Scapy (2.3.3.dev483)
Random Fuzzer v0.5
>>> mf=test(output_dir)
```

The execution can be followed by the output on screen.

5. After the Fuzzing Campaign finishes, use CTRL+C to exit:
```python
[22:05.50] Stopping AUT...
[22:05.50] ... Stopped!
>>> 
SIGINT Received
[22:05.51] Stopping AUT...
[22:05.51] ... Stopped!
```

6. The Process Monitor can be killed as well:
```sh
$ pkill -f process_monitor
```

7. Finally, all output files and reports should have been generated:
```sh
$ ls -lht out_r/cantcoap-server/1/
```

### Offline Analysis
...TODO basic tutorial.