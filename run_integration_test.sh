#!/bin/sh

ret=0

if [ -n $KA_SPEC_RUN_INTEGRATION ]; then
  source integration_test_support/environment
fi

run_bacon ( ) {
  if [ -f $library_path ]; then
    echo $library_name
    FFI_KRB5_LIBRARY_NAME=$library_path bacon -a
    ret=$(($ret+$?))
    echo ''
  fi
}

library_name='MacPorts MIT'
library_path='/opt/local/lib/libkrb5.dylib'
run_bacon

library_name='OS X Heimdal'
library_path='/usr/lib/libkrb5.dylib'
run_bacon

library_name='Debian Heimdal'
library_path='/usr/lib/x86_64-linux-gnu/libkrb5.so.26'
run_bacon

library_name='Debian MIT'
library_path='/usr/lib/x86_64-linux-gnu/libkrb5.so.3'
run_bacon

exit $ret