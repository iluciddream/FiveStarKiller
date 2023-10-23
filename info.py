from collections import namedtuple

select_info = namedtuple('select_info', ['NIC', 'Protocol', 'SrcAddr', 'DstAddr'])

# 创建一个结构体对象
info = select_info('WLAN', 'TCP', '192.168.1.0', '192.168.1.1')

# 访问结构体的参数
print(info.NIC)  # 输出: a
print(info.Protocol)  # 输出: b
print(info.SrcAddr)  # 输出: c
print(info.DstAddr)  # 输出: d