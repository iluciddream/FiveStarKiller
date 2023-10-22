import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *

import tkinter as tk
from tkinter import ttk

import tkinter as tk
from tkinter import messagebox

def option_selected():
    selected_nic_option = option_nic.get()
    selected_protocol_option = option_protocol.get()

    selected_src = src_entry.get()
    selected_dst = dst_entry.get()

    messagebox.showinfo("选择结果", f"你选择了: {selected_nic_option}{selected_protocol_option}")
    messagebox.showinfo("选择结果", f"你选择了: {selected_src}{selected_dst}")

root = tk.Tk()
root.title("开始界面")

# filter selection 创建下拉菜单
nic_label = tk.Label(root, text="NIC")
nic_label.pack(pady=10)
option_nic = tk.StringVar(root)
option_nic.set("ALL")  # 设置默认选项
option_nic_menu = tk.OptionMenu(root, option_nic, "ALL", "ETH0", "WLAN")
option_nic_menu.pack(pady=20)
protocol_label = tk.Label(root, text="协议类型")
protocol_label.pack(pady=10)
option_protocol = tk.StringVar(root)
option_protocol.set("ALL")  # 设置默认选项
option_protocol_menu = tk.OptionMenu(root, option_protocol, "ALL", "TCP", "UDP", "HTTP")
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
