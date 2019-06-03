#!/bin/bash

if [ "$#" -ne 1 ]
then
  echo "Please supply a path to a clean folder"
  echo "Usage: ./get_sources [path_to_a_clean_folder]"
  exit 1
fi

echo "----------------------------------------------------------------------------"
echo "Downloading sawtooth-sdk-cxx"
echo "----------------------------------------------------------------------------"

if [ ! -d sawtooth-sdk-cxx ]; then
	git clone https://github.com/hyperledger/sawtooth-sdk-cxx --branch v0.1.1
fi

echo "----------------------------------------------------------------------------"
echo "Copying source files except Business logic and config.cpp to" $1
echo "----------------------------------------------------------------------------"

mkdir -p -m 777 $1/src/

cp -Rf sawtooth-sdk-cxx/. $1/sawtooth-sdk-cxx/
cp -Rf src/AccessControlLogic/. $1/src/AccessControlLogic/
cp -Rf src/ClientReader/. $1/src/ClientReader/
mv $1/src/Common/config.cpp $1/src/Common/config_temp.cpp
cp -Rf src/Common/. $1/src/Common/
mv $1/src/Common/config_temp.cpp $1/src/Common/config.cpp
cp -Rf src/CryptoLib/. $1/src/CryptoLib/
cp -Rf src/lib/. $1/src/lib/
cp -Rf src/Listener/. $1/src/Listener/
cp -Rf src/Main/. $1/src/Main/
cp -Rf src/Network/. $1/src/Network/
cp -Rf src/ServerSync/. $1/src/ServerSync/
cp -Rf private_rest_api/. $1/private_rest_api/


echo "--------"
echo " Done"
echo "--------"




