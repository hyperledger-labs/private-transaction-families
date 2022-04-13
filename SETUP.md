# Setup Guide

# Introduction

This document describes how to install and setup Private-Transaction-Families 
system on top of Hyperledger Sawtooth Transaction Processor.

Hyperledger Sawtooth components do not depend on any other component of the 
project, and can be set up on an entirely separate machine from the one running
the Private-Transaction-Families.

Hyperledger Sawtooth is validated on Ubuntu* 16.04 which is the recommended OS.

Private-Transaction-Families is intended to execute on Intel® SGX-enabled 
platforms (Intel® Software Guard eXtension). However, it can also get executed 
in "simulator mode" on platforms that do not have HW support for Intel® SGX.

Private-transaction-families is supported on one a single node as well as on 
multi nodes.

## Pre Requisites

1. Intel based platform with Intel® SGX support (available on Intel 7th gen 
   processor and above).Note: In order to test on simulation mode 
   (non-production), no need for Intel® SGX support in hardware.
3. Ubuntu 16.04
4. Intel® SGX SDK
5. Hyperledger Sawtooth 1.1 (latest)

## Operating System

1. Install Ubuntu 16.04
2. Connect to the Network with active internet connection
3. install latest Ubuntu updates by running the commands:
   sudo apt-get update
   sudo apt-get upgrade

## Install Intel® Software Guard Extension (SGX)

The SGX SDK is required for both hardware-mode and simulator-mode deployments. 
Private-Transaction-Families is built and tested against version 2.2 of the SGX
SDK (Note: newer versions should be supported).

1. Intel® SGX SDK
   - Download the driver and SDK installers from: 
     [https://01.org/intel-software-guard-extensions/downloads](https://01.org/intel-software-guard-extensions/downloads)
   - Get the latest Linux release - Intel® SGX Installers for Ubuntu* 16.04
      sgx_linux_x64_driver_<version>.bin and sgx_linux_x64_sdk_<version>.bin
   - Add permissions: `$ sudo chmod u+x ./sgx_linux_x64_sdk_<version>.bin`
   - Install the SDK: `$ sudo ./sgx_linux_x64_sdk_<version>.bin`
     do not install on current directory, install the sdk under /opt/intel
     Note the instructions to set the environment variable after SDK 
     installation is complete.
   - Set Intel® SGX source environment by default:
     Edit the file .bashrc (hidden file in the home folder) and add the SGX SDK
     folder at the end of the file: "source /opt/intel/sgxsdk/environment"
     where <sgx sdk install path> is the path to where SDK was installed

2. If you are using an Intel® SGX supported platform (required for hardware mode), 
   install Intel® SGX Platform Software (PSW) and driver.
   - Download the PSW installer and driver from: 
     [https://download.01.org/intel-sgx/linux-2.1.3/ubuntu64-desktop/](https://download.01.org/intel-sgx/linux-2.1.3/ubuntu64-desktop/) (Later releases may be available)
     **or** build the latest PSW release available on
     [https://github.com/01org/linux-sgx](https://github.com/01org/linux-sgx).
   - Add permissions: `$ sudo chmod u+x ./sgx_linux_x64_psw_<version>.bin`
   - Install the PSW: `$ sudo ./sgx_linux_x64_psw_<version>.bin`
   - Add permissions: `$ sudo chmod u+x ./ sgx_linux_x64_driver_<version>.bin`
   - Install the driver: `$ sudo ./sgx_linux_x64_driver_<version>.bin`

More information about Intel® SGX on Linux is available here:
 - [https://github.com/intel/linux-sgx](https://github.com/intel/linux-sgx)
 - [https://download.01.org/intel-sgx/linux-2.1.3/docs/Intel_SGX_Installation_
    Guide_Linux_2.1.3_Open_Source.pdf](https://download.01.org/intel-sgx/linux-2.1.3/docs/Intel_SGX_Installation_Guide_Linux_2.1.3_Open_Source.pdf)
 - [https://github.com/intel/linux-sgx-driver](https://github.com/intel/linux-sgx-driver)

## Install Hyperledger Sawtooth Blockchain

1. The instructions below are based on the Hyperledger Sawtooth Installation guide
   [https://sawtooth.hyperledger.org/docs/core/releases/latest/
    app_developers_guide/ubuntu.html#](https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/ubuntu.html)
1. Install the latest stable release of Hyperledger Sawtooth 1.1:
   - Install via apt-get:
   
         `$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys
         8AA7AF1F1091A5FD`    
         `$ sudo add-apt-repository 'deb [arch=amd64] http://repo.sawtooth.me/ubuntu/
         bumper/stable xenial universe'`         
         `$ sudo apt-get update`         
         `$ sudo apt-get install -y sawtooth`         
         `$ sudo apt-get install -y -q sawtooth-devmode-engine-rust`          
         (Note: this last command is for dev mode, can use any consensus you want)
   
   - Continue the installation based on the procedure (you may stop at 
     "Starting the validator" step)
1. Check that Hyperledger Sawtooth 1.1 was successfully installed: 
   `$dpkg -l "*sawtooth*"`

## Install Sawtooth cpp dependencies

The following dependencies need to be installed after Hyperledger Sawtooth 
installation:
 - Install GIT:  `$ sudo apt install git`
 - Install Cmake:  `$ sudo apt install cmake`
 - Install ZMQ: `$ sudo apt-get install libzmqpp3`
 - Install Log4cxx: `$ sudo apt-get install liblog4cxx10v5`
 - Install Protobuf as explained in GIT (We tested with Protobuf 3.6 and 3.5.1):
   [https://github.com/google/protobuf/blob/master/src/README.md](https://github.com/google/protobuf/blob/master/src/README.md)
   - Download and extract the cpp release from:
     [https://github.com/protocolbuffers/protobuf/releases/tag/v3.6.1](https://github.com/protocolbuffers/protobuf/releases/tag/v3.6.1)
   - `$ ./configure CXXFLAGS="$(pkg-config --cflags protobuf)"\`
     `$ LIBS="$(pkg-config --libs protobuf)" --prefix=/usr`
   - `$ sudo make`
   - `$ sudo make check` (may be skipped)
   - `$ sudo make install`
   - `$ sudo ldconfig`

## Compile the Transaction Processor (TP)

Note: if you don't wish to compile the TP sources you can skip this step and 
just run it (see instructions in the [USAGE](USAGE.md) document).

1. Install Hyperledger Sawtooth C++ SDK dependencies:
   - Log4cxx dev files -  `$ sudo apt-get install liblog4cxx10-dev`
   - Zmqpp dev files - `$ sudo apt-get install libzmqpp-dev`
   - Cryptopp - `$ sudo apt-get install libcrypto++-dev`
   - Pthread should already be installed `$ locate libpthread.a`, 
      if pthread is missing, install it with the following command - 
      `$ sudo apt-get install libpthread-stubs0-dev`
   - Python tools - `$ sudo apt-get install python3-setuptools`

2. Clone the latest [Private-Transaction-Families](https://github.com/tzimer/private-transaction-families) sources from git
3. Install private rest api
   - `$ cd private_rest_api/rest_api`
   - `$ ./compile_proto`
   - `$ sudo python3 setup.py install`

4. install sawtooth c++ SDK
   - Goto [Private-transaction-families](./) folder.
   - `$ git clone https://github.com/hyperledger/sawtooth-sdk-cxx`
   - Go to sawtooth-sdk-cxx directory `$ cd sawtooth-sdk-cxx` and run
   - `$ ./bin/build_cxx_sdk`
5. Compile TP code:
   - Install libcurl - `$ sudo apt-get install libcurl4-openssl-dev`
   - `$ cd src/Main` (under [Private-transaction-families](./) folder)
   - `$ make SGX_DEBUG=1 SGX_MODE=SIM` (for SGX supported HW - SGX_MODE=HW)
     In order to run with production SGX (SGX release mode), you will need 
     to follow the Intel® SGX whitelist process as documented in:
     [https://software.intel.com/sites/default/files/managed/ae/2e/
      Enclave-Signing-Tool-for-Intel-SGX.pdf](https://software.intel.com/sites/default/files/managed/ae/2e/Enclave-Signing-Tool-for-Intel-SGX.pdf)

6. Continue with [usage guide](USAGE.md)
     
     
