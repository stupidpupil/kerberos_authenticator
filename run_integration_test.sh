#!/bin/sh

source integration_test_support/environment

echo 'Use MacPorts MIT library' 
FFI_KRB5_LIBRARY_NAME=/opt/local/lib/libkrb5.dylib bacon -a

echo ''
echo 'Use OS X Heimdal library'
FFI_KRB5_LIBRARY_NAME=/usr/lib/libkrb5.dylib bacon -a