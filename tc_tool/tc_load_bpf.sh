#!/bin/bash

ARG=$1
if [ -z "$ARG" ];then
	inf_name=eth0
else
	inf_name=$ARG
fi

obj_path=$(dirname $0)
ingress_obj_file=${obj_path}/bpf_udp_change_ingress.bpf
egress_obj_file=${obj_path}/bpf_udp_change_egress.bpf

has_qdisc=$(tc qdisc show dev ${inf_name} | grep clsact)
if [ -z "${has_qdisc}" ];then
	tc qdisc add dev ${inf_name} clsact
fi
tc filter del dev ${inf_name} ingress 
tc filter del dev ${inf_name}  egress

tc filter add dev ${inf_name} ingress bpf da obj ${ingress_obj_file} sec tc_udp_ingress
tc filter add dev ${inf_name} egress bpf da obj ${egress_obj_file} sec tc_udp_egress

tc filter show dev ${inf_name} ingress
tc filter show dev ${inf_name} egress
