#!/bin/bash
 
echo '------------'
echo 'cd build'
echo '------------'
# Build and run test
if [[ -d ./build/ ]] ; then
    cd build
else
    mkdir build
    cd build
fi
echo '------------'
echo 'run cmake ..'
echo '------------'
cmake ..
echo '------------'
echo 'run make'
echo '------------'
make clean
make
echo '------------'
echo 'run tests'
echo '------------'
for D in */; do ./"$D"TEST_*; done

echo '------------'
echo 'get coverage results'
echo '------------'
# get basic results
lcov -b . -d . -c -o .code_res.info
echo '------------'
echo 'remove coverage results of unit test code and /usr* filse'
echo '------------'
# remove result about unit test code
lcov -r .code_res.info "Test/*" -o .code_res.info
lcov -r .code_res.info "/usr*" -o .code_res.info
echo '------------'
echo 'generate index.html report'
echo '------------'
if [[ -d ./html/ ]] ; then
    rm -rf ./html/*
else
    mkdir html
fi
genhtml -o ./html/ .code_res.info
# Extra: Preserve coverage file in coveragehistory folder
[[ -d ./coveragehistory/ ]] || mkdir coveragehistory
cp .code_res.info ./coveragehistory/`date +'%Y.%m.%d-coverage'`
echo '------------'
echo 'firefox ./html/index.html'
echo '------------'
firefox ./html/index.html &

rm .code_res.info
