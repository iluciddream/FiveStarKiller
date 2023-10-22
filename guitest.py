import tkinter as tk

def show_details(data):
    # 创建新窗口
    window = tk.Toplevel()
    
    # 在新窗口中显示详细数据
    label = tk.Label(window, text=data)
    label.pack()

# 创建主窗口
root = tk.Tk()

# 假设有一些数据
data_list = ['数据1', '数据2', '数据3']

# 在主窗口中显示数据列表
for data in data_list:
    button = tk.Button(root, text=data, command=lambda d=data: show_details(d))
    button.pack()

# 运行主窗口的事件循环
root.mainloop()


from tkinter import *
from tkinter import ttk

def create_table_header(table, headers):
    for i, header in enumerate(headers):
        table.heading(i, text=header)

def create_table_data(table, data):
    for row in data:
        table.insert('', 'end', values=row)

root = Tk()
root.title("Table GUI")

# 创建表格
table = ttk.Treeview(root)

# 创建表头
headers = ['Name', 'Age', 'Gender']
create_table_header(table, headers)

# 创建表格数据
data = [
    ['John', '25', 'Male'],
    ['Mary', '30', 'Female'],
    ['Tom', '35', 'Male']
]
create_table_data(table, data)

# 设置表格样式
table.pack(pady=10)
table.column("#0", width=0, stretch=NO)  # 隐藏第一列

# 运行GUI
root.mainloop()