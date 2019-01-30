#!/bin/bash

# set -x # enable this for debugging this script

# move to the folder where the script is located
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Build directory is $PROJECT_ROOT"

# make sure openssl tarball is present
OPENSSL_VERSION=`/bin/ls $PROJECT_ROOT/*.tar.gz | /usr/bin/head -1 | /bin/grep -o '[^/]*$' | /bin/sed -s -- 's/\.tar\.gz//'`
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

# remove old copy
rm -rf $OPENSSL_VERSION

# cleanup old builds
rm -rf $PROJECT_ROOT/lib/*
rm -rf $PROJECT_ROOT/include/openssl/*

# extract openssl and move into the folder
tar xvf $OPENSSL_VERSION.tar.gz || exit 1
cd $PROJECT_ROOT/$OPENSSL_VERSION || exit 1

# prepare openssl _release_ configuration and build
perl Configure linux-x86_64 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-ssl3 no-md2 no-md4 no-ui -D_FORTIFY_SOURCE=2 --prefix=$PROJECT_ROOT/tmp_output
make -j2 build_generated libcrypto.so libssl.a || exit 1

# copy the required libraries
cp libcrypto.a $PROJECT_ROOT/lib/libcrypto.a || exit 1
cp libssl.a $PROJECT_ROOT/lib/libssl.a || exit 1
cp libcrypto.so.1.1 $PROJECT_ROOT/lib/libcrypto_so.so.1.1 || exit 1

# remove previous release build
cd $PROJECT_ROOT
rm -rf $OPENSSL_VERSION

# extract openssl and move into the folder
tar xvf $OPENSSL_VERSION.tar.gz || exit 1
cd $PROJECT_ROOT/$OPENSSL_VERSION || exit 1

# prepare openssl _debug_ configuration and build
perl Configure -g linux-x86_64 enable-crypto-mdebug no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-ssl3 no-md2 no-md4 no-ui --prefix=$PROJECT_ROOT/tmp_output
make -j2 build_generated libcrypto.so libssl.a || exit 1

# copy the required libraries
cp libcrypto.a $PROJECT_ROOT/lib/libcryptod.a || exit 1
cp libssl.a $PROJECT_ROOT/lib/libssld.a || exit 1
cp libcrypto.so.1.1 $PROJECT_ROOT/lib/libcryptod_so.so.1.1 || exit 1

# copy the headers from the debug build - contains a few more function which are used in debug builds
cp include/openssl/* $PROJECT_ROOT/include/openssl/ || exit 1

# create shared objects symbolic links
cd $PROJECT_ROOT/lib
ln -s libcrypto_so.so.1.1 libcrypto_so.so | exit 1
ln -s libcryptod_so.so.1.1 libcryptod_so.so | exit 1

# cleanup
cd $PROJECT_ROOT
rm -rf $OPENSSL_VERSION

echo "build ended successfully"

exit 0

