#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
sys.dont_write_bytecode = True
import base64
import binascii
import datetime
import socket
import dpkt

def mac_addr(addr):
	from dpkt.compat import compat_ord
	return ":".join("%02x"%compat_ord(b) for b in addr)

def inet_to_str(inet):
	try:
		return socket.inet_ntop(socket.AF_INET, inet)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, inet)

if __name__ == "__main__":
	ss = ""
	f = open("pcap-name.pcap")
	pcap = dpkt.pcap.Reader(f)
	for i,(ts,buf) in enumerate(pcap):
		dt = datetime.datetime.utcfromtimestamp(ts)
		eth = dpkt.ethernet.Ethernet(buf)
		if isinstance(eth.data, dpkt.ip.IP):
			ip = eth.data
			do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
			more_fragments = bool(ip.off & dpkt.ip.IP_MF)
			fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
			tcp = ip.data
			src_ip,src_port = inet_to_str(ip.src),tcp.sport
			dst_ip,dst_port = inet_to_str(ip.dst),tcp.dport
			if tcp.data:
				ss += tcp.data
				sys.stdout.write(tcp.data)
				sys.stdout.flush()
