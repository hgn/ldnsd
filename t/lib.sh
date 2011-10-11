#!/bin/sh

export LIB_INITIALIZED
export dig
export E_PATH

LIB_INITIALIZED=

set_daemon_exec_path()
{
	if ! test -x ".././ldnsd"
	then
		echo "no daemon executable found"
		exit 666
	fi
	E_PATH=".././ldnsd"
}

initialize()
{
	if ! test -z $LIB_INITIALIZED
	then
		return
	fi

	echo "initialize test library"

	set_daemon_exec_path

	dig=$(whereis -b dig | awk '{print $2}')
	if test -z $dig
	then
		echo "no dig installed"
		exit 666
	fi

	LIB_INITIALIZED=1
}

initialize
initialize
