# fuzzcoap
FuzzCoAP is a system comprising a complete environment for testing robustness and security aspects of CoAP server-side implementations and applications. Five black-box fuzzing techniques were implemented in FuzzCoAP: Random, Informed Random, Mutational, Smart Mutational and Generational fuzzers. It was designed and implemented during the production of my MSc. Dissertation, and used to test 25 samples (applications), covering 25 different CoAP libraries (implementations) distributed across 8 programming languages, including samples from IoT-specific operating systems RIOT OS and Contiki-NG. FuzzCoAP was able to detect a total of 100 failures in 14 out of the 25 tested samples.

Needless to say, but this goes to **disclaimer**: This is, of course, experimental code. Everything still needs a little bit of refactoring and general polishing. Currently, the Fuzzer is more solid than the offline analyzer scripts, and, between those, the `an_packets.py` script is really not in the best shape it could have been. With a little patience for reading the code, though, it's definetely usable and useful. So, yeah, borrowing from the MIT License (which captures this in a more direct and concise way): "THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED (...)".


## Installation
### Option 1: Vagrant VM
Note: The text below is based on [RIOT OS' Vagrant README.md](https://github.com/RIOT-OS/RIOT/blob/2018.04-branch/dist/tools/vagrant/README.md).

This repository includes a [Vagrantfile](Vagrantfile) to download and control a pre-configured Linux virtual machine (VM) based on an Ubuntu Server 16.04 (64-bit) image that contains all samples used in our research (see our [Target List](target_list.py)), with their respective dependencies and build systems installed. In that VM, not only the samples are ready-to-use, but FuzzCoAP as well. Using this method you will be able to jump to [Using FuzzCoAP](#using-fuzzcoap).

#### Requirements
Make sure your system satisfies the latest version of all following dependencies:
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* [VirtualBox Extension Pack](https://www.virtualbox.org/wiki/Downloads)
* [Vagrant](https://www.vagrantup.com/downloads.html)

#### General usage
1. Clone this repository:
```sh
$ git clone https://github.com/bsmelo/fuzzcoap
```
The following commands must be run from the FuzzCoAP root directory on the host system.


2. Start up the virtual machine and download the Ubuntu image --- which might take a [good] while...:
```sh
$ vagrant up
```

3. Login to the VM as the vagrant user:
```
vagrant ssh
```

You can now jump to [Using FuzzCoAP](#using-fuzzcoap).
Ps.: Before distributing the VM usign Vagrant Cloud, I missed one update from the Scapy patch and forgot to install one extra dependency; so:
```sh
$ cd scapy/
# Copy and apply relevant patches (of course the first argument here needs to be changed accordingly)
$ cp ~/fuzzcoap/001-Scapy-for-CoAP-and-Additional-Volatiles-for-Fuzzing.patch .
$ git apply 001-Scapy-for-CoAP-and-Additional-Volatiles-for-Fuzzing.patch
$ sudo python setup.py install

$ sudo pip install pygdbmi
```

- To gracefully shut down the VM:
```
vagrant halt
```

- To reset the VM to the default state:
```
vagrant destroy
```

#### Inside the VM
Once logged in to the VM via `vagrant ssh` you can find the FuzzCoAP root directory in your working directory (on the guest system). This is a shared directory and stays synchronized with your FuzzCoAP directory on the host system. All changes made will be mirrored from the host system to the guest system and vice versa. Just start fuzzing by jumping to [Using FuzzCoAP](#using-fuzzcoap).


### Option 2: Host/Native Machine
First of all, clone this repository:
```sh
$ git clone https://github.com/bsmelo/fuzzcoap
```

#### Dependencies
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
[pygdbmi](https://pypi.org/project/pygdbmi/), which we use to interface with `gdb` in `an_crashlist.py`:
```sh
sudo pip install pygdbmi
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
#### Distinguishing Failures and Identifying Root Causes
To be able to distinguish between failures, we assign failure identificators, composed by filename|line_no|function_name, based on the deepest frame from the stacktrace from which we can extract a filename. Using this identifier we can find out which failures are duplicated and which ones are unique failures.

`an_crashlist`: parses the `crashlist.log` file and, for each test case number in there, reads the corresponding `core` file (if available). Then, by interfacing with the `gdb` debugger, loads the SUT binary configured together with the core file, obtaining the stacktrace from a given failure. Example:

```sh
python an_crashlist.py -t contiki-native-erbium-plugtest -d output/contiki-ng-er/
```

`an_target`: parses the `target.log` file. Since its format is dependent on the SUT (mainly the SUT programming language), the stacktrace format differs between them. Similarly to the previous one, is able to assign a failure identificator to each failure found, based on the stacktrace parsed. Example:

```sh
python an_target.py -t canopus-server -d out/canopus-test/
```

#### Reproducing Failures
`an_packets`: Reproduces each failure from a specified input list of test case numbers by replaying the packets related to each of those test cases to the SUT. Example:

In Terminal 1, start the SUT:
```sh
python /home/vagrant/coap-apps/CoAPthon/coapserver.py
```

In Terminal 2, run the analyzer script (`sudo` required by Scapy to exchange packets):
```sh
sudo python an_packets.py -t coapthon-server -d out/coapthon-test/
```

#### Extracting Fuzzing Campaign Execution Metrics
`tr.csv`: Template Results. Lists all templates used in the campaign (note that the components of the Template Details varies between different engines) together with the number of crashes, number of TCs generated, number of TCs actually executed and the time taken to run that template.

`ftc.csv`: Failed Test Cases. List all TCs in which a failure was detected, containing the following fields: Option Name, Template Details and TC Number. Since the reported TC is the one in which the crash was detected, not the one which actually caused the SUT to crash, what we do is to [manually] merge this information with the information obtained through either `an_crashlist` or `an_target` to obtain an accurate piece.