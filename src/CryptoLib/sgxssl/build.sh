#!/bin/bash

# set -x # enable this for debugging this script

# move to the folder where the script is located
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Build directory is $PROJECT_ROOT"

# make sure openssl tarball is present
OPENSSL_VERSION=`/bin/ls $PROJECT_ROOT/openssl*.tar.gz | /usr/bin/head -1 | /bin/grep -o '[^/]*$' | /bin/sed -s -- 's/\.tar\.gz//'`
if [ "$OPENSSL_VERSION" == "" ] 
then
	echo "In order to run this script, OpenSSL tar.gz package must be located in the same directory as this build script"
	echo "You can download it from https://www.openssl.org/source/, please download the latest 1.1.0 version"
	exit 1
fi
echo "OpenSSL version is $OPENSSL_VERSION"

if [[ "$OPENSSL_VERSION" != *"1.1.0"* ]]; then
	echo "Currently only OpenSSL 1.1.0 is supported"
	exit 1
fi

# get a fresh copy of sgx-ssl
rm -rf intel-sgx-ssl
git clone https://github.com/intel/intel-sgx-ssl.git || exit 1

# cleanup old builds
rm -rf $PROJECT_ROOT/lib64/*
rm -rf $PROJECT_ROOT/include/*

# put the openssl tarball in the right place for sgx-ssl build
cp $PROJECT_ROOT/$OPENSSL_VERSION.tar.gz $PROJECT_ROOT/intel-sgx-ssl/openssl_source || exit 1

# copy changed files (adding tls support)
cd revised_files || exit 1
cp bypass_to_sgxssl.h $PROJECT_ROOT/intel-sgx-ssl/openssl_source/bypass_to_sgxssl.h || exit 1
cp build_openssl.sh $PROJECT_ROOT/intel-sgx-ssl/Linux/build_openssl.sh || exit 1
cp sgx_tsgxssl.edl $PROJECT_ROOT/intel-sgx-ssl/Linux/package/include/sgx_tsgxssl.edl || exit 1
cp tdirent.cpp $PROJECT_ROOT/intel-sgx-ssl/Linux/sgx/libsgx_tsgxssl/tdirent.cpp || exit 1
cp tunistd.cpp $PROJECT_ROOT/intel-sgx-ssl/Linux/sgx/libsgx_tsgxssl/tunistd.cpp || exit 1
cp uunistd.cpp $PROJECT_ROOT/intel-sgx-ssl/Linux/sgx/libsgx_usgxssl/uunistd.cpp || exit 1

# todo - need to solve the problem with CRYPTO_mem_leaks_fp - talk to Alaa
sed -i "s|OPENSSL_NO_CRYPTO_MDEBUG|OPENSSL_NO_STDIO|g" $PROJECT_ROOT/intel-sgx-ssl/Linux/sgx/test_app/enclave/tests/dhtest.c
sed -i "s|OPENSSL_NO_CRYPTO_MDEBUG|OPENSSL_NO_STDIO|g" $PROJECT_ROOT/intel-sgx-ssl/Linux/sgx/test_app/enclave/tests/ectest.c
sed -i "s|OPENSSL_NO_CRYPTO_MDEBUG|OPENSSL_NO_STDIO|g" $PROJECT_ROOT/intel-sgx-ssl/Linux/sgx/test_app/enclave/tests/rsa_test.c
sed -i "s|OPENSSL_NO_CRYPTO_MDEBUG|OPENSSL_NO_STDIO|g" $PROJECT_ROOT/intel-sgx-ssl/Linux/sgx/test_app/enclave/tests/ecdhtest.c

# move into the build folder
cd $PROJECT_ROOT/intel-sgx-ssl/Linux || exit 1

# build sgx-ssl _release_
make all SGX_MODE=HW || exit 1
mv $PROJECT_ROOT/intel-sgx-ssl/Linux/package/lib64/* $PROJECT_ROOT/lib64 || exit 1
make clean

# build sgx-ssl _debug_
make all DEBUG=1 SGX_MODE=HW || exit 1
mv $PROJECT_ROOT/intel-sgx-ssl/Linux/package/lib64/* $PROJECT_ROOT/lib64 || exit 1
mv $PROJECT_ROOT/intel-sgx-ssl/Linux/package/include/* $PROJECT_ROOT/include || exit 1

# cleanup
cd $PROJECT_ROOT || exit 1
rm -rf intel-sgx-ssl

# now build aes_siv library
$PROJECT_ROOT/build_aes_siv.sh || exit 1

echo "build ended successfully"

exit 0

