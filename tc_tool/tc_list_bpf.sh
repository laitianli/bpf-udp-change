#!/bin/bash


ARG=$1
if [ -z "$ARG" ];then
	inf_name=eth0
else
	inf_name=$ARG
fi



tc filter show dev ${inf_name} ingress
tc filter show dev ${inf_name} egress
