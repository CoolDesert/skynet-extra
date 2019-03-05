#!/bin/sh
export ROOT=$(cd `dirname $0`; pwd)
export DAEMON=false

while getopts "Dkl" arg
do
	case $arg in
		D)
			export DAEMON=true
			;;
		k)
			kill `cat $ROOT/bin/skynet.pid`
			exit 0;
			;;
		l)
			# backup logfile
			filename="`date +"%F_%T"`.log"
			mv $ROOT/bin/skynet.log $ROOT/bin/$filename
			# to reopen logfile , we need send SIGHUP to skynet
			kill -1 `cat $ROOT/bin/skynet.pid`
			exit 0;
			;; 
	esac
done

$ROOT/skynet/skynet $ROOT/config

