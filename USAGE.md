# Private Transaction Families Usage instructions

## Pre Requisites

Install all components as explained in the [setup guide](SETUP.md)

## Generate the ledger keys

1. the following tools can be found under 'out' folder:
    - kds_calculator - a tool to calculate kds (key derivation secret) for a 
      certain svn, from a given bds (base derivation secret)
     - kds_signer - tool to generate a kds signature with the administrator
       key (located under ~/.stl_keys/admin_private[public]_key.hexstr)
     - client_keys_creator - generates new EC key pair and places it in the 
       current folder

2.  If you do not want to use multi node, you can use the fake ledger keys 
    located in the genesis_files folder:
    - ias-test-as.spid - includes the Service Provider ID you got
      from Intel Attestation Services 
      (for example 887710ADAD9321C614316EC06F277331)
    - ias-test-as.key - the key provided on the IAS portal for your connections
    - kds.hexstr - the Key Derivation Secret to use for creating the private 
      ledger keys (for example 
      123456789012345678901234567890123456789012345678901234567890ABCD)
    - kds_signature.hexstr - the KDS signature, created with the ledger's 
      administrator key. **Note: the public part of this key must match the 
      string in src/Common/config.cpp!**

3. run from out folder:`$ ./keys_creation`, this creates the following files:
   - ~/.stl_keys/ledger_sealed_keys.data - sealed secret keys 
     (kds and IAS data), can only be opened by the enclave on this machine
   - ~/.stl_keys/ledger_public_ra_key.data - remote attestation keys (used for 
     multi node deployment)
   - ~/.stl_keys/ledger_public_data_key.hexstr - should be copied to any client 
     who wants to transmit encrypted transactions or read requests to the 
     ledger
   - **Note: if the SVN increases, this commands should be executed again, and 
     new keys are created**

## Running Hyperledger Sawtooth

Clear the ledger, generate Hyperledger Sawtooth keys and genesis batch,  start 
the validator, the rest API, the setting-tp, the consensus engine and 
private-tp with the restart sawtooth script:

 - `$ sudo chmod u+x restart_sawtooth.sh`
 - `$ sudo ./restart_sawtooth [-vvv] ` (-vvv is optional for verbose log)

## Compiling a transaction generator client

Transaction generator is available as an example for submitting private 
transactions.

 - `$ cd transaction_generator`
 - `$ sudo apt-get install python3-setuptools`
 - `$ sudo apt-get install python3-jsonschema`
 - `$ sudo python3 setup.py install`

## Submitting transactions

For development usage, generate client member key pair: 
    
    `$ ./out/client_keys_creator`

An example client key is available under [Debug/client1_keys](./Debug/client1_keys])
For production usage, use your preferred method for key generation and 
handling (HSM, Vault, others...)

The transaction generator is using a config json file. An example of a config 
json file can be found under /Debug/txn_gen_example.json 

Create and load private batch:

    `$ private-txn-generator create_batch -f path/to/config/file.json`
    `$ private-txn-generator load`

To verify that transactions were submitted, check the Hyperledger Sawtooth 
state and logs.

## Running read request script

Go to [Debug/client_reader](Debug/client_reader) folder and run 

    `$ python3 read_request.py <address> -K <client public key>`

  

# MULTI NODE CONFIGURATION

## Sharing keys for multi node environment

In order to deploy multiple nodes, the sealed ledger keys need to be shared 
between the different nodes. The Server sync component is using Intel® SGX 
attestation to pass the keys in a secured channel between the nodes.
Note: The keys are unique for each system based on its hardware keys. 
You cannot copy the keys manually and therefore have to run the following 
procedure:
1. Register with Intel Attestation Services:
   - Join the IAS portal at [https://api.portal.trustedservices.intel.com/](https://api.portal.trustedservices.intel.com/)
   - Subscribe to the unlinkable EPID attestation service at [https://api.portal.trustedservices.intel.com/EPID-attestation](https://api.portal.trustedservices.intel.com/EPID-attestation)

2. Generate the following files and place them under the genesis files folder
(/out/genesis_files).
   - ias-test-as.spid - includes the Service Provider ID you got from Intel 
     Attestation Services (for example 887710ADAD9321C614316EC06F277331)
   - ias-test-as.key - The key provided on your IAS panel
   - kds.hexstr - the Key Derivation Secret used for creating the private 
     ledger keys (for example 
     123456789012345678901234567890123456789012345678901234567890ABCD)
3. Copy the ~/.stl_keys/ledger_public_ra_key.data to any machine that 
   participates in the blockchain network
4. On the machine that generated the keys (the server machine), run: 
   `$ ./keys_server`
5. On the machine that doesn't have the keys and need to get them run: 
   `$ ./keys_client <server machine IP>`

## Optional: Attaching a debugger to a running TP using vscode

For debugging Intel® SGX enclave there is a dedicated debugger. An example of 
debugger configuration can be found in the debug folder ([launch.json](./Debug/launch.json)). 
Edit the sgx gdb location according to where you installed the SGX SDK.
