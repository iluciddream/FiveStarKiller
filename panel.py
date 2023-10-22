import tkinter as tk

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


class DetailFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        
        self.name_label = tk.Label(self, text="")
        self.name_label.pack()
        
        self.description_label = tk.Label(self, text="")
        self.description_label.pack()
        
    def show_detail(self, data):
        self.name_label.config(text="\n" + data["name"])
        self.description_label.config(text="Packet Details:\n"+data["description"] + "\nPacket in Binary:\n" + data["raw"])
        ""



class MainFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        
        self.data = [
            {"name": "Packet 1 Detected","description": " ICMP Packet Detected:Source IP: 10.207.255.254\n Destination IP   : 10.207.119.48\n Source MAC       : 30:7b:ac:69:38:02\n Destination MAC  : dc:71:96:f5:3a:4d\n IP Version       : 4", "raw":"01 00 02 45 00 21 11 11"},
            {"name": "Data 2", "description": "This is data 2.", "raw": "00 01 11 10"},
            {"name": "Data 3", "description": "This is data 3.", "raw": "00 01 11 10"}
        ]
        
        self.data_bars = []
        
        self.data_bar_frame = tk.Frame(self)
        self.data_bar_frame.pack()
        
        self.detail_frame = DetailFrame(self)
        self.detail_frame.pack()
        
        for data in self.data:
            data_bar = DataBar(self.data_bar_frame, data, self.detail_frame)
            data_bar.pack(side="top")
            self.data_bars.append(data_bar)


if __name__ == "__main__":
    root = tk.Tk()
    app = MainFrame(root)
    app.pack()
    root.mainloop()