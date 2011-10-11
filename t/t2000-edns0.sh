#!/bin/sh

. ./lib.sh

# please use this test only if caching is enabled

$dig +retry=0 +bufsize=512 +qr -p 6666 small.nxdomain.se TXT @localhost
