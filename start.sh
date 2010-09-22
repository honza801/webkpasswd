#!/bin/bash

PID="cherryd.pid"
LOG=""
CONFIG="webkpasswd.conf"
IMPORT="webkpasswd"

case "$1" in 
	-i) 
		IMPORT=$2
		shift 2
	;;
	-log)
		LOG="-f >cherryd.log 2>&1 &"
		shift
	;;
	*)
		echo "unknown option"
	;;
esac

[ -f $PID ] && kill `cat $PID`
cherryd --config=$CONFIG --import=$IMPORT --pidfile=$PID $LOG 

