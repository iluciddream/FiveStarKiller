from collections import namedtuple
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *
import tkinter as tk
from tkinter import ttk
import tkinter as tk
from tkinter import messagebox
from scapy.all import *
from info import select_info
from scapy.layers.inet import IP
"""
# define the sturct to record and pass selected info
nic = None
protocol = None
src_addr = None
dst_addr = None
"""

# 可缺省的抓包函数
def capture_packets(nic=None, protocol=None, src_addr=None, dst_addr=None):
    print(nic,protocol,src_addr,dst_addr)
    packets = sniff(iface=nic, filter=protocol, count=30, lfilter=lambda pkt: IP in pkt and (src_addr is None or pkt[IP].src == src_addr) and (dst_addr is None or pkt[IP].dst == dst_addr))
    for packet in packets:
        print(packet.summary())
    return packets


class DetailFrame(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        
        self.scrollbar = tk.Scrollbar(self)
        self.scrollbar.pack(side="right", fill="y")
        
        self.text = tk.Text(self, yscrollcommand=self.scrollbar.set)
        self.text.pack(side="left", fill="both", expand=True)
        
        self.scrollbar.config(command=self.text.yview)
        
    def show_detail(self, data):
        self.text.delete(1.0, tk.END)
        self.text.insert(tk.END, "\n" + data["name"])
        self.text.insert(tk.END, "\n" + data["description"])


class MainFrame(tk.Frame):
    def __init__(self, master, packets):
        super().__init__(master)
        self.master = master

        self.datas = []
        self.data_index = 0
        
        for packet in packets:
            description = packet.show(dump=True)
            data = {
                "name": packet.summary(),
                "description": description,
            }
            self.datas.append(data)

        self.data_bars = []
        
        self.canvas_frame = tk.Frame(self)
        self.canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        self.canvas = tk.Canvas(self.canvas_frame)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.scrollbar = tk.Scrollbar(self.canvas_frame, command=self.canvas.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        self.detail_frame = DetailFrame(self.master)
        
        self.show_next_data()
    
    def show_next_data(self):
        if self.data_index < len(self.datas):
            data = self.datas[self.data_index]
            data_bar = DataBar(self.canvas, data, self.detail_frame)
            self.canvas.create_window((0, len(self.data_bars) * 30), window=data_bar, anchor="nw")
            self.data_bars.append(data_bar)
            self.data_index += 1
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
            self.after(2000, self.show_next_data)
            
class DataBar(tk.Frame):
    def __init__(self, master, data, detail_frame):
        super().__init__(master)
        self.master = master
        self.data = data
        self.detail_frame = detail_frame
        
        self.label = tk.Label(self, text=data["name"])
        self.label.pack(side="left")
        self.label.bind("<Button-1>", self.show_detail)
        
    def show_detail(self, event):
        self.detail_frame.show_detail(self.data)


def option_selected():
    selected_nic_option = option_nic.get()
    selected_protocol_option = option_protocol.get()
    selected_src = src_entry.get()
    selected_dst = dst_entry.get()

    messagebox.showinfo("选择结果", f"你选择了: {selected_nic_option}{selected_protocol_option}")
    messagebox.showinfo("选择结果", f"你选择了: {selected_src}{selected_dst}")

    nic_select = option_nic.get()
    protocol_select = option_protocol.get()
    src_addr_select = src_entry.get()
    dst_addr_select = dst_entry.get()
    print(nic_select, protocol_select, src_addr_select, dst_addr_select)
    if(nic_select=="ALL"):
        nic_select=None
    if(protocol_select=="ALL"):
        protocol_select=None
    if(src_addr_select==""):
        src_addr_select=None
    if(dst_addr_select==""):
        dst_addr_select=None
    print(nic_select, protocol_select, src_addr_select, dst_addr_select)

    root = tk.Tk()
    nic_select='WLAN' #for debugging
    packets = capture_packets(nic=nic_select, protocol=protocol_select, src_addr=src_addr_select, dst_addr=dst_addr_select)
    app = MainFrame(root,packets)
    app.pack()

root = tk.Tk()
root.title("开始界面")

# filter selection
nic_label = tk.Label(root, text="NIC")
nic_label.pack(pady=10)
option_nic = tk.StringVar(root)
option_nic.set("ALL") 
option_nic_menu = tk.OptionMenu(root, option_nic, "ALL", "WLAN", "Ether")
option_nic_menu.pack(pady=20)
protocol_label = tk.Label(root, text="协议类型")
protocol_label.pack(pady=10)
option_protocol = tk.StringVar(root)
option_protocol.set("ALL")  # 设置默认选项
option_protocol_menu = tk.OptionMenu(root, option_protocol, "ALL", "icmp", "ip", "tcp", "udp", "arp", "dhcp", "dns", "ftp", "http")
option_protocol_menu.pack(pady=20)
# src dst selection
src_label = tk.Label(root, text="源地址")
src_label.pack(pady=10)
src_entry = tk.Entry(root)
src_entry.pack()
dst_label = tk.Label(root, text="目的地址")
dst_label.pack(pady=10)
dst_entry = tk.Entry(root)
dst_entry.pack()

# start sniffing 创建一个按钮，用于提交选择
submit_btn = tk.Button(root, text="Start Sniffing", command=option_selected)
submit_btn.pack()

root.mainloop()

