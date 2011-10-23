#!/bin/sh

. ./lib.sh

# please use this test only if caching is enabled

$dig +notcp +retry=0 +bufsize=512 +qr -p 6666 small.nxdomain.se TXT @localhost
$dig +notcp +retry=0 +bufsize=4096 +qr -p 6666 medium.nxdomain.se TXT @localhost
#$dig +retry=0 +bufsize=512 +qr -p 6666 large.nxdomain.se TXT @localhost
#$dig +retry=0 +bufsize=512 +qr -p 6666 huge.nxdomain.se TXT @localhost
