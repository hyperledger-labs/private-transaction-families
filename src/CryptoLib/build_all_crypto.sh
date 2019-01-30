#!/bin/bash

# set -x # enable this for debugging this script

# modify this value if needed
LATEST_OPENSSL="openssl-1.1.0i"

echo "This script will download $LATEST_OPENSSL.tar.gz from OpenSSL website."
echo "If there is a newer OpenSSL 1.1.0 version, please update this script."
echo "After downloading, this script will build OpenSSL 4 times (for enclave and for app usage, release and debug)."
echo "This might take a few minutes..."
read -p "Press any key to start"

# move to the folder where the script is located
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# make sure openssl tarball is present, if not, download it
OPENSSL_VERSION=`/bin/ls $PROJECT_ROOT/openssl*.tar.gz | /usr/bin/head -1 | /bin/grep -o '[^/]*$' | /bin/sed -s -- 's/\.tar\.gz//'`
if [ "$OPENSSL_VERSION" == "" ] 
then
	wget https://www.openssl.org/source/$LATEST_OPENSSL.tar.gz || exit 1
fi

# build openssl libraries
mv $PROJECT_ROOT/$LATEST_OPENSSL.tar.gz $PROJECT_ROOT/openssl/$LATEST_OPENSSL.tar.gz || exit 1
cd $PROJECT_ROOT/openssl || exit 1
./build.sh || exit 1

# build sgxssl libraries
mv $PROJECT_ROOT/openssl/$LATEST_OPENSSL.tar.gz $PROJECT_ROOT/sgxssl/$LATEST_OPENSSL.tar.gz || exit 1
cd $PROJECT_ROOT/sgxssl || exit 1
./build.sh || exit 1

rm $PROJECT_ROOT/sgxssl/$LATEST_OPENSSL.tar.gz || exit 1

# build stl crypto libraries
cd $PROJECT_ROOT || exit 1
make clean all || exit 1

exit 0

