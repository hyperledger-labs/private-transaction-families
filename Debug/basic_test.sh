#!/bin/bash
cd ..
echo "-------------------------------------------"
echo "compiling private-tp"
echo "-------------------------------------------"
cd src/Main/
make clean
make SGX_DEBUG=1 SGX_MODE=SIM
cd ../..
echo "-------------------------------------------"
echo "creating keys"
echo "-------------------------------------------"
cd out
./keys_creation
cd ..
echo "-------------------------------------------"
echo "starting environment"
echo "-------------------------------------------"
cd Debug
sudo ./restart_sawtooth.sh -vvv
echo "-------------------------------------------"
echo "submit svn txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_gen_svn.json 
private-txn-generator load
echo "-------------------------------------------"
echo "submit acl txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_gen_acl.json 
private-txn-generator load
echo "-------------------------------------------"
echo "submit txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_gen_example.json 
private-txn-generator load
echo "-------------------------------------------"
echo "sawtooth state list"
echo "-------------------------------------------"
sleep 1s
sawtooth state list
echo "-------------------------------------------"
echo "reading address"
echo "-------------------------------------------"
cd client_reader
python3 read_request_new.py -A bb563a905f1957a0dd5fbf218d5d402d303ecec6ee9e33cf5c6715a1d148fd73f73188 -K ../client1_keys
python3 read_request.py bb563a905f1957a0dd5fbf218d5d402d303ecec6ee9e33cf5c6715a1d148fd73f73188 -K ../client1_keys
