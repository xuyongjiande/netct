#!/bin/bash

function ip2num()
{
	local ip=$1
	a=`echo $ip | awk -F '.' '{print $1}' `
	b=`echo $ip | awk -F '.' '{print $2}' `
	c=`echo $ip | awk -F '.' '{print $3}' `
	d=`echo $ip | awk -F '.' '{print $4}' `

	echo $(((d<<24)+(c<<16)+(b<<8)+a))
}

#__DROP_SYN=1		# 0x01
#__DROP_SYN_ACK=2	# 0x02
#__DROP_ACK=4		# 0x04

function usage()
{
	echo -e "$1 __drop_type __drop_index __drop_num\n"
	echo -e "__drop_type :\tIn Handshake Phase, support __DROP_SYN(value: 1), __DROP_SYN_ACK(value: 2), __DROP_ACK(value: 4)"
	echo -e "\t\tIn  Establish Phase, if __drop_type == 16, means reordering"
	echo -e "__drop_index:\tFor Establish Phase, control S to C data, specify which packet is discarded"
	echo -e "__drop_num  :\tIn  Handshake Phase, specify the number corresponding to the packet discards , including retransmission"
	echo -e "\t\tIn  Establish Phase, if __drop_index != 0, specify the number corresponding to the packet discards , including retransmission"
	echo -e "\t\tIn  Establish Phase, if __drop_index == 0, supports up to eight field, according to spaces to separate, no support drop retransmission"
}

if [ $# -ne 4 ]; then
	usage $0
	exit 0
fi

__DROP_NUM=$3
if [ $1 -eq 0 -a $2 -eq 0 ]; then
	drop_num=0
	loop=0
	for i in $__DROP_NUM; do
		drop_num=`echo $((((i&0xF)<<(loop*4))+drop_num))`
		loop=$((loop+1))
	done
	if [ $loop -gt 8 ]; then
		echo "__drop_num supports up to eight field, according to spaces to separate"
		exit 1
	fi
	__DROP_NUM=$drop_num
	#printf "__DROP_NUM: %x\n" $__DROP_NUM
fi
	
#sip="10.217.87.205"
#sip="10.42.0.72"
#sip="192.168.0.122"
sip="10.42.0.13"
dip="202.108.7.249"
#dip="10.216.27.43"
#dip="10.216.25.43"
dport=80

rmmod hook
#insmod ./hook.ko __src_ip=$(ip2num $1) __dst_ip=$(ip2num $2) __dst_port=$3 __drop_index=$4 __drop_num=$5 __drop_type=4
#echo "insmod ./hook.ko __src_ip=$(ip2num $sip) __dst_ip=$(ip2num $dip) __dst_port=$dport __drop_type=$1 __drop_index=$2 __drop_num=$__DROP_NUM"
#insmod ./hook.ko __dir=1 __src_ip=$(ip2num $sip) __dst_ip=$(ip2num $dip) __dst_ip2=$(ip2num $dip2) __dst_port=$dport __drop_type=$1 __drop_index=$2 __drop_num=$__DROP_NUM 
insmod ./hook.ko __src_ip=$(ip2num $sip) __dst_ip=$(ip2num $dip) __dst_port=$dport __drop_type=$1 __drop_index=$2 __drop_num=$__DROP_NUM __dir=$4

