#!/bin/sh
export LD_LIBRARY_PATH=/opt/oqssa/lib:/opt/oqssa/lib64:$LD_LIBRARY_PATH
export OPENSSL_MODULES=/opt/oqssa/lib64/ossl-modules
exec /usr/local/bin/ztunnel "$@"
