#!/usr/bin/env python
import scapy.all as scapy
import optparse
import smtplib

def get_parameters():
	parser=optprase.OptionParser()
	parser.add_option("-i", "--interface",dest="interface",help="provide interface to run")
	(options, argument)=parser.parse_args()
	if not options.interface:
		parser.error("use --help for more info")
	return options

def get_mac(ip):
    arp_request =scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processed_sniff_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:

            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac!=response_mac:
                print("[+] You are under ARP Attack!!")
		server=smtplib.SMTP("smtp.gmail.com",578)
		server.starttls()
		server.login(email, passwd)
		server.sendmail(email,passwd,"you are under attack")
        except IndexError:
            pass

options = get_parameters()
interface = options.interface
sniff(interface)
