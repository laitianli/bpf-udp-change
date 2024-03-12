#!/bin/bash


ARG=$1
if [ -z "$ARG" ];then
	inf_name=eth0
else
	inf_name=$ARG
fi


has_qdisc=$(tc qdisc show dev ${inf_name} | grep clsact)
if [ -z "${has_qdisc}" ];then
	exit 0
fi

tc filter del dev ${inf_name} ingress 
tc filter del dev ${inf_name}  egress


tc filter show dev ${inf_name} ingress
tc filter show dev ${inf_name} egress


tc qdisc del dev ${inf_name} clsact
