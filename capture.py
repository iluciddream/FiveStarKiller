from scapy.all import *

def packet_callback(packet):
    wrpcap('captured.pcap', packet, append=True)
    
# 开始抓包
sniff(prn=packet_callback, count=100)