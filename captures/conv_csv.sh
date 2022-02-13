#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "USAGE: ./conv_csv.sh [PCAP-FILE]"
    exit 1
fi

FILE=$1

tshark -r $FILE -T fields -e eth.src -e eth.dst -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e _ws.col.Protocol -E header=y -E separator=, -E quote=d -E occurrence=f > $FILE.csv
