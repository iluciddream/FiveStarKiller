from scapy.all import *


from scapy.layers.inet import IP

def capture_packets(nic=None, protocol=None, src_addr=None, dst_addr=None):
    print(nic,protocol,src_addr,dst_addr)
    packets = sniff(iface=nic, filter=protocol, count=10, lfilter=lambda pkt: IP in pkt and (src_addr is None or pkt[IP].src == src_addr) and (dst_addr is None or pkt[IP].dst == dst_addr))
    #for packet in packets:
        #print(packet.summary())
    return packets

n='ETHERNET'
# WLAN
p='tcp'

# Example usage:
#pks1=capture_packets(nic='Ether', protocol='tcp', src_addr='192.168.1.1', dst_addr='192.168.1.2')
# All parameters are specified
#print(pks1.summary())
pks2=capture_packets(nic=n, protocol=p)
# Only nic and protocol are specified, src_addr and dst_addr are None
print(pks2.summary())
#pks3=capture_packets()
# Only nic is specified, protocol, src_addr, and dst_addr are None
#print(pks3.summary())
capture_packets()
# All parameters are None, default behavior will be used