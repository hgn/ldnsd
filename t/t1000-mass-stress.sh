#!/bin/sh

. ./lib.sh

# please use this test only if caching is enabled

for i in $(seq 1 100)
do
	$dig +retry=0 -p 6666 -t a jauu.net @localhost
	echo "return $?"
done
