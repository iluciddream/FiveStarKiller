
from scapy.all import *
from scapy.layers.inet import IP

def capture_packets(nic=None, protocol=None, src_addr=None, dst_addr=None):
    print(nic,protocol,src_addr,dst_addr)
    packets = sniff(iface=nic, filter=protocol, count=10, lfilter=lambda pkt: IP in pkt and (src_addr is None or pkt[IP].src == src_addr) and (dst_addr is None or pkt[IP].dst == dst_addr))
    #for packet in packets:
        #print(packet.summary())
    return packets

packets= capture_packets()

datas = []
for packet in packets:
    data = {
        "name": packet.summary(),
        "description": packet.show(),
        #"raw": packet.show()
    }
    datas.append(data)

for data in datas:
    print(data["name"])
    print(data["description"])
    #print(data["raw"])
  
