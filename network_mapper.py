#!/usr/bin/python3

import argparse
from scapy.all import *

def get_args():
	parser = argparse.ArgumentParser(description='A simple network scanning tool.')
	parser.add_argument('-t','--target',help='Target IP or Subnet to scan.',dest='target')
	args = parser.parse_args()
	if not args.target:
		parser.error("[+] Please enter the target IP/range.")
	return parser.parse_args()

def scan(ip):
	arp_req_broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
	ans,unans = srp(arp_req_broadcast, timeout=1, verbose=False)
	#print(ans.summary())

	clients = []
	for element in ans:
		client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
		clients.append(client_dict)
	return clients

def print_result(clients):
	print("IP Address\t\tMAC Address\n----------------------------------------------")
	for client in clients:	
		print(client['ip'] + '\t\t' + client['mac'])


args = get_args()
clients = scan(args.target)
print_result(clients)