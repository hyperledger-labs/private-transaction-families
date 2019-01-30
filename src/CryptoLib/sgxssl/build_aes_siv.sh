#!/bin/bash

# set -x # enable this for debugging this script

# move to the folder where the script is located
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "Build directory is $PROJECT_ROOT"

# build the aes_siv library

# use offline copy of the repository, prevent attacks by someone replacing the files in git
# copy downloaded at 22-aug-2018
#rm -rf libaes_siv
#git clone https://github.com/dfoxfranke/libaes_siv.git || exit 1

cd $PROJECT_ROOT/libaes_siv || exit 1

cp CMakeLists.txt CMakeLists_orig.txt || exit 1

# add fPIC build flag
sed -i "s|-ftree-vectorize|-ftree-vectorize -fPIC -nostdinc -Wno-implicit-function-declaration -I$SGX_SDK/include/tlibc|g" $PROJECT_ROOT/libaes_siv/CMakeLists.txt

# build _release_ with SGX-SSL
cmake -DOPENSSL_INCLUDE_DIR=$PROJECT_ROOT/include -DCMAKE_BUILD_TYPE=Release . || exit 1
make aes_siv_static || exit 1
cp libaes_siv.a $PROJECT_ROOT/lib64/libaes_siv.a || exit 1
make clean || exit 1

# build _debug_ with SGX-SSL
cmake -DOPENSSL_INCLUDE_DIR=$PROJECT_ROOT/include -DCMAKE_BUILD_TYPE=Debug . || exit 1
make aes_siv_static || exit 1
cp libaes_siv.a $PROJECT_ROOT/lib64/libaes_sivd.a || exit 1

# this file goes to the parent directory, since placing it in the include folder creates conflicts in the unit tests
cp aes_siv.h $PROJECT_ROOT/../aes_siv.h || exit 1

# cleanup
make clean || exit 1
rm -rf CMakeFiles || exit 1
rm CMakeCache.txt || exit 1
rm cmake_install.cmake || exit 1
rm CTestTestfile.cmake || exit 1
rm Makefile || exit 1
rm config.h || exit 1
rm CMakeLists.txt || exit 1

mv CMakeLists_orig.txt CMakeLists.txt || exit 1

cd $PROJECT_ROOT

#rm -rf libaes_siv

exit 0

