import tkinter as tk
import subprocess
from tkinter import scrolledtext, filedialog, ttk
from scapy.all import sniff, wrpcap
from scapy.all import IP
import threading
from datetime import datetime
from tkinter import messagebox
import customtkinter
from PIL import ImageTk,Image
import socket,sys,time,os

customtkinter.set_appearance_mode("dark")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("green")  # Themes: blue (default), dark-blue, green


app = customtkinter.CTk()  #creating cutstom tkinter window

app.geometry("{}x{}+0+0".format(app.winfo_screenwidth(),app.winfo_screenheight())) 
app.title('Login')


img1=ImageTk.PhotoImage(Image.open("./assets/pattern1.jpg"))
l1=customtkinter.CTkLabel(master=app,image=img1)
l1.pack()


app_frame=customtkinter.CTkFrame(master=l1, width=800, height=700, corner_radius=15)
def ping_feature():
    def ping():
        target = ping_entry.get()
        try:
            result =subprocess.run(["ping", target], capture_output=True, text=True, timeout=10)
            ping_results_text.configure(state=customtkinter.NORMAL)
            ping_results_text.delete(1.0, customtkinter.END)
            ping_results_text.insert(customtkinter.END, result.stdout)
            ping_results_text.configure(state=customtkinter.DISABLED)
        except subprocess.CalledProcessError:
            ping_results_text.configure(state=customtkinter.NORMAL)
            ping_results_text.delete(1.0, customtkinter.END)
            ping_results_text.insert(customtkinter.END, "Ping failed.")
            ping_results_text.configure(state=customtkinter.DISABLED)
        except subprocess.TimeoutExpired:
            ping_results_text.configure(state=customtkinter.NORMAL)
            ping_results_text.delete(1.0, customtkinter.END)
            ping_results_text.insert(customtkinter.END, "Ping timed out.")
            ping_results_text.configure(state=customtkinter.DISABLED)

    ping_feature_page=customtkinter.CTkFrame(master=work_frame, width=800, height=600, corner_radius=15)

    label1=customtkinter.CTkLabel(master=ping_feature_page, text="Ping_Feature_Page",font=('Century Gothic',20))
    label1.place(x=50, y=45)
    ping_entry_label = customtkinter.CTkLabel(master=ping_feature_page, text="Target IP/Hostname:",font=('Century Gothic',20),width=300,height=50)
    ping_entry_label.place(x=250,y=100)
    ping_entry = customtkinter.CTkEntry(master=ping_feature_page,width=300,height=50,font=('Century Gothic',20))
    ping_entry.place(x=250,y=175)
    ping_button = customtkinter.CTkButton(master=ping_feature_page, text="Ping", command=ping,width=200,height=50)
    ping_button.place(x=300,y=275)
    ping_results_text = customtkinter.CTkTextbox(master=ping_feature_page, width=700, height=200)
    ping_results_text.place(x=50,y=375)
    ping_results_text.configure(state=customtkinter.DISABLED)  # Make it read-only
    ping_feature_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)



def traceroute():

    def trace():
        target = trace_entry.get()
        try:
            result = subprocess.run(["tracert", target], capture_output=True, text=True, timeout=60)
            trace_results_text.configure(state=customtkinter.NORMAL)
            trace_results_text.delete(1.0, customtkinter.END)
            trace_results_text.insert(customtkinter.END, result.stdout)
            trace_results_text.configure(state=customtkinter.DISABLED)
        except subprocess.CalledProcessError as e:
            trace_results_text.configure(state=customtkinter.NORMAL)
            trace_results_text.delete(1.0, customtkinter.END)
            trace_results_text.insert(customtkinter.END, f"Trace route failed : {str(e)}")
            trace_results_text.configure(state=customtkinter.DISABLED)
        except subprocess.TimeoutExpired:
            trace_results_text.configure(state=customtkinter.NORMAL)
            trace_results_text.delete(1.0, customtkinter.END)
            trace_results_text.insert(customtkinter.END, "Trace route timed out.")
            trace_results_text.configure(state=customtkinter.DISABLED)

    traceroute_page=customtkinter.CTkFrame(master=work_frame, width=800, height=600, corner_radius=15)
    traceroute_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    label2=customtkinter.CTkLabel(master=traceroute_page, text="Traceroute_Page ",font=('Century Gothic',20))
    label2.place(x=50, y=45)
    trace_entry_label = customtkinter.CTkLabel(master=traceroute_page , text="Target IP/Hostname:",font=('Century Gothic',20),width=300,height=50)
    trace_entry_label.place(x=250,y=100)
    trace_entry = customtkinter.CTkEntry(master=traceroute_page ,width=300,height=50,font=('Century Gothic',20))
    trace_entry.place(x=250,y=175)
    trace_bt = customtkinter.CTkButton(master=traceroute_page , text="Traceroute", command=trace,width=200,height=50)
    trace_bt.place(x=300,y=275)
    trace_results_text = customtkinter.CTkTextbox(master=traceroute_page , width=700, height=200)
    trace_results_text.place(x=50,y=375)
    trace_results_text.configure(state=customtkinter.DISABLED)  # Make it read-only

PROTOCOL_NAMES = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

def snipper():
   

    class PacketAnalyzer:
        def __init__(self, master):
            self.master = master
            
            self.master.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
            self.tree_columns = ["Time", "Source IP", "Destination IP", "Protocol", "Length"]

            self.tree = ttk.Treeview(master, columns=self.tree_columns, show="headings", selectmode="browse")
            for col in self.tree_columns:
                self.tree.heading(col, text=col)
            self.tree.grid(row=0, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

            self.transmission_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=10)
            self.transmission_text.grid(row=1, column=0, columnspan=4, padx=10, pady=10, sticky="nsew")

            self.network_adapter_label = tk.Label(master, text="Select Network Adapter:")
            self.network_adapter_label.grid(row=2, column=0, padx=30, pady=5, sticky="w")

            self.adapter_var = tk.StringVar()
            self.adapter_var.set("Wi-Fi")  # Default selection
            self.wifi_radio = tk.Radiobutton(master, text="Wi-Fi", variable=self.adapter_var, value="Wi-Fi")
            self.wifi_radio.grid(row=2, column=1, padx=50, pady=5, sticky="w")
            self.ethernet_radio = tk.Radiobutton(master, text="Ethernet", variable=self.adapter_var, value="Ethernet")
            self.ethernet_radio.grid(row=2, column=2, padx=30, pady=5, sticky="w")

            self.ip_search_label = tk.Label(master, text="Search IP:")
            self.ip_search_label.grid(row=3, column=0, padx=65, pady=5, sticky="w")

            self.ip_search_entry = tk.Entry(master, width=20)
            self.ip_search_entry.grid(row=3, column=1, padx=15, pady=5, sticky="w")

            self.ip_range_label = tk.Label(master, text="IP Range (Start-End):")
            self.ip_range_label.grid(row=4, column=0, padx=35, pady=5, sticky="w")

            self.start_ip_entry = tk.Entry(master, width=20)
            self.start_ip_entry.grid(row=4, column=1, padx=15, pady=5, sticky="w")
            #tk.Label(master, text="-").grid(row=4, column=2, pady=5, sticky="w")
            self.end_ip_entry = tk.Entry(master, width=20)
            self.end_ip_entry.grid(row=4, column=2, padx=5, pady=5, sticky="w")

          #  self.protocol_label = tk.Label(master, text="Select Protocol:")
           #
            #self.protocol_var = tk.StringVar()
            #self.protocol_var.set("All")
            #self.protocol_dropdown = ttk.Combobox(master,width=17, values=["All"] + list(PROTOCOL_NAMES.values()), textvariable=self.protocol_var)
            #self.protocol_dropdown.grid(row=5, column=1, columnspan=2, padx=15, pady=5, sticky="w")

            self.apply_range_button = tk.Button(master,width=20, text="Apply Range", command=self.search_packets)
            self.apply_range_button.grid(row=4, column=3, columnspan=2, padx=10, pady=5, sticky="w")

            #self.search_button = tk.Button(master,width=20, text="Search", command=self.search_packets)
            #self.search_button.grid(row=5, column=3, columnspan=2, padx=10, pady=5, sticky="w")

            self.start_button = tk.Button(master,width=20, text="Start Capturing", command=self.start_sniffing)
            self.start_button.grid(row=2, column=3, columnspan=2, padx=10, pady=5, sticky="w")

            self.stop_button = tk.Button(master,width=20, text="Stop Capturing", command=self.stop_sniffing)
            self.stop_button.grid(row=3, column=3, columnspan=2, padx=10, pady=5, sticky="w")
            self.stop_button["state"] = "disabled"

            self.save_button = tk.Button(master, text="Save Packets", command=self.save_packets)
            self.save_button.grid(row=8, column=0, columnspan=4, padx=10, pady=10, sticky="ew")

            self.file_path_entry = tk.Entry(master, width=50)
            self.file_path_entry.grid(row=9, column=0, columnspan=4, padx=10, pady=5, sticky="ew")

            self.sniffing_thread = None
            self.stop_sniffing_flag = threading.Event()
            self.packets = []
            self.ongoing_transmission = []

            for col in self.tree_columns:
                self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c, False))
            
            # Create the right-click menu
            self.right_click_menu = tk.Menu(master, tearoff=0)
            self.right_click_menu.add_command(label="Scan Open Port ", command=self.launch_port_scanner)
            self.right_click_menu.add_command(label="Ping", command=self.launch_utilities)
            self.right_click_menu.add_command(label="TraceRoute", command=self.launch_utilities)
            self.right_click_menu.add_command(label="BlockIP", command=self.launch_ip_blocker)
            
            # Binding right-click event
            self.tree.bind("<Button-3>", self.show_right_click_menu)


        def show_right_click_menu(self, event):
            item = self.tree.selection()[0]
            self.right_click_menu.post(event.x_root, event.y_root)

    # def scan_selected_ip(self):
            #self.launch_port_scanner(ip)
            #selected_item = self.tree.selection()[0]
            #selected_ip = self.tree.item(selected_item, 'values')[1]  # Assuming IP is at index 1
            #self.launch_port_scanner(selected_ip)

        
        def launch_port_scanner(self):
         subprocess.Popen(["python", "PortScanner.py"])
        
        def launch_utilities(self):
            subprocess.Popen(["python", "Utilities.py"])

        def launch_ip_blocker(self):
            subprocess.Popen(["python", "ipblocker.py", "--gui"])

        def format_time(self, timestamp):
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

        def search_packets(self):
            search_ip = self.ip_search_entry.get().strip()
            search_protocol = self.protocol_var.get()

            start_ip = self.start_ip_entry.get().strip()
            end_ip = self.end_ip_entry.get().strip()

            filtered_packets = [packet for packet in self.packets if
                                (search_ip in (packet[1].lower(), packet[2].lower()) or search_ip == "") and
                                (search_protocol == "All" or PROTOCOL_NAMES.get(packet[3], "").lower() == search_protocol.lower()) and
                                (self.is_ip_in_range(packet[1], start_ip, end_ip) or self.is_ip_in_range(packet[2], start_ip, end_ip) or start_ip == "" or end_ip == "")]

            self.display_packets(filtered_packets)

        def is_ip_in_range(self, ip, start, end):
            try:
                start_ip = self.ip_to_int(start)
                end_ip = self.ip_to_int(end)
                current_ip = self.ip_to_int(ip)
                return start_ip <= current_ip <= end_ip
            except ValueError:
                return False

        def ip_to_int(self, ip):
            return int(''.join([f"{int(octet):03}" for octet in ip.split('.')]))

        def display_packets(self, packets):
            self.tree.delete(*self.tree.get_children())
            for packet in packets:
                self.tree.insert("", tk.END, values=packet, tags=("found" if self.ip_search_entry.get().lower() in (packet[1].lower(), packet[2].lower()) else ""))

        def sort_column(self, col, reverse):
            items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
            items.sort(reverse=reverse)

            for index, (val, k) in enumerate(items):
                self.tree.move(k, '', index)

            self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))

        def start_sniffing(self):
            self.start_button["state"] = "disabled"
            self.stop_button["state"] = "normal"
            self.save_button["state"] = "normal"

            self.stop_sniffing_flag.clear()
            self.packets = []
            self.ongoing_transmission = []
            self.tree.delete(*self.tree.get_children())
            self.transmission_text.delete(1.0, tk.END)  # Clear the transmission text
            self.sniffing_thread = threading.Thread(target=self.sniff_packets)
            self.sniffing_thread.start()

        def stop_sniffing(self):
            self.start_button["state"] = "normal"
            self.stop_button["state"] = "disabled"
            self.save_button["state"] = "normal"

            if self.sniffing_thread:
                self.stop_sniffing_flag.set()
                self.sniffing_thread.join()

        def sniff_packets(self):
            adapter_name = self.adapter_var.get()
            print("Using network adapter:", adapter_name)  # Print the adapter name for debugging

            def packet_callback(packet):
                if self.stop_sniffing_flag.is_set():
                    return

                protocol_num = "N/A"

                if IP in packet:
                    packet_time = self.format_time(packet.time)
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    protocol_num = packet[IP].proto if IP in packet else "N/A"
                    protocol_name = PROTOCOL_NAMES.get(protocol_num, 'N/A')

                    length = len(packet)
                    info = packet.summary()

                if protocol_num in [6, 17]:
                    if src_ip != 'N/A' and dst_ip != 'N/A' and protocol_name != 'N/A':
                        self.packets.append((packet_time, src_ip, dst_ip, protocol_name, length, info))
                        self.tree.insert("", tk.END, values=(packet_time, src_ip, dst_ip, protocol_name, length, info))

                        # Store ongoing transmissions
                        self.ongoing_transmission.append((packet_time, src_ip, dst_ip, protocol_name, length, info))
                        self.display_transmission()

            sniff(iface=adapter_name, prn=packet_callback, stop_filter=lambda _: self.stop_sniffing_flag.is_set())

        def display_transmission(self):
            self.transmission_text.delete(1.0, tk.END)  # Clear the transmission text
            for packet in self.ongoing_transmission:
                self.transmission_text.insert(tk.END, f"{', '.join(map(str, packet))}\n")
            self.transmission_text.insert(tk.END, "\n")

        def save_packets(self):
            file_path = self.file_path_entry.get().strip()
            if not file_path:
                file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
                self.file_path_entry.delete(0, tk.END)
                self.file_path_entry.insert(0, file_path)

            if file_path:
                wrpcap(file_path, self.packets)
                print(f"Packets saved to {file_path}")

    def main():
        snipper=tk.Frame(master=work_frame, width=800, height=600)
        app = PacketAnalyzer(snipper)
    

    if __name__ == "__main__":
        main()


    # ==== IP Blocker Functions ====
def ip_block():

    def rule_exists(rule_name):
        result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=" + rule_name], capture_output=True, text=True)
        return "No rules match the specified criteria." not in result.stdout

# Function to block outbound traffic to an IP using Windows Firewall
    def block_outbound_ip(ip):
        try:
            rule_name = "BlockOutboundIP"
            if not rule_exists(rule_name):
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=" + rule_name, "dir=out", "action=block",f"remoteip={ip}/32"])
            else:
                subprocess.run(["netsh", "advfirewall", "firewall", "set", "rule", "name=" + rule_name, f"new remoteip={ip}/32"])
            messagebox.showinfo("Success", f" traffic to IP {ip} blocked successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block  traffic to IP {ip}: {str(e)}")

        # Function to unblock outbound traffic to an IP using Windows Firewall
    def unblock_outbound_ip(ip):
        try:
            rule_name = "BlockOutboundIP"
            if rule_exists(rule_name):
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=" + rule_name])
                messagebox.showinfo("Success", f" traffic to IP {ip} unblocked successfully.")
            else:
                messagebox.showinfo("Info", f"Outbound traffic to IP {ip} was not blocked.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock  traffic to IP {ip}: {str(e)}")


    ip_block_page=customtkinter.CTkFrame(master=work_frame, width=800, height=600, corner_radius=15)

    label =customtkinter.CTkLabel(ip_block_page, text="Enter IP Address:",font=('Century Gothic',30))
    label.place(x=275, y=125)
    ip_entry =customtkinter.CTkEntry(ip_block_page, width=300 ,height=50)
    ip_entry.place(x=250, y=225)
    block_button = customtkinter.CTkButton(ip_block_page, text="Block  IP", width=300 ,height=50, command=lambda: block_outbound_ip(ip_entry.get()))
    block_button.place(x=250, y=325)
    unblock_button = customtkinter.CTkButton(ip_block_page, text="Unblock  IP", width=300 ,height=50, command=lambda: unblock_outbound_ip(ip_entry.get()))
    unblock_button.place(x=250, y=425)
        
    ip_block_page.place(relx=0.5, rely=0.5, anchor=tk.CENTER)


ip_s = 1
ip_f = 1024
log = []
ports = []
target = 'localhost'

def port_scanner():

    # ==== Scanning Functions ====
    def scanPort(target, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            c = s.connect_ex((target, port))
            if c == 0:
                m = ' Port %d \t[open]' % (port,)
                log.append(m)
                ports.append(port)
                listbox.insert("end", str(m))
                updateResult()
            s.close()
        except OSError: print('> Too many open sockets. Port ' + str(port))
        except:
            c.close()
            s.close()
            sys.exit()
        sys.exit()
        
    def updateResult():
        rtext = " [ " + str(len(ports)) + " / " + str(ip_f) + " ] ~ " + str(target)
        L27.configure(text = rtext)

    def startScan():
        global ports, log, target, ip_f
        clearScan()
        log = []
        ports = []
        # Get ports ranges from GUI
        ip_s = int(L24.get())
        ip_f = int(L25.get())
        # Start writing the log file
        log.append('> Port Scanner')
        log.append('='*14 + '\n')
        log.append(' Target:\t' + str(target))
        
        try:
            target = socket.gethostbyname(str(L22.get()))
            log.append(' IP Adr.:\t' + str(target))
            log.append(' Ports: \t[ ' + str(ip_s) + ' / ' + str(ip_f) + ' ]')
            log.append('\n')
            # Lets start scanning ports!
            while ip_s <= ip_f:
                try:
                    scan = threading.Thread(target=scanPort, args=(target, ip_s))
                    scan.setDaemon(True)
                    scan.start()
                except: time.sleep(0.01)
                ip_s += 1
        except:
            m = '> Target ' + str(L22.get()) + ' not found.'
            log.append(m)
            listbox.insert(0, str(m))
            
    def saveScan():
        global log, target, ports, ip_f
        log[5] = " Result:\t[ " + str(len(ports)) + " / " + str(ip_f) + " ]\n"
        with open('portscan-'+str(target)+'.txt', mode='wt', encoding='utf-8') as myfile:
            myfile.write('\n'.join(log))

    def clearScan():
        listbox.delete(0, 'end')

    L11 = customtkinter.CTkLabel(work_frame, text = "Port Scanner",  font=("Helvetica", 16, 'underline'))
    L11.place(x = 16, y = 10)

    L21 = customtkinter.CTkLabel(work_frame, text = "Target: ")
    L21.place(x = 16, y = 90)

    L22 = customtkinter.CTkEntry(work_frame)
    L22.place(x = 180, y = 90)
    L22.insert(0, "localhost")

    L23 = customtkinter.CTkLabel(work_frame, text = "Ports: ")
    L23.place(x = 16, y = 158)

    L24 = customtkinter.CTkEntry(work_frame, width = 95)
    L24.place(x = 180, y = 158)
    L24.insert(0, "1")

    L25 = customtkinter.CTkEntry(work_frame, width = 95)
    L25.place(x = 290, y = 158)
    L25.insert(0, "1024")

    L26 = customtkinter.CTkLabel(work_frame, text = "Results: ")
    L26.place(x = 16, y = 220)
    L27 = customtkinter.CTkLabel(work_frame, text = "[ ... ]")
    L27.place(x = 180, y = 220)

    # ==== Ports list ====
    frame = tk.Frame(work_frame)
    frame.place(x = 25, y = 375, width = 800, height = 215)
    listbox = tk.Listbox(frame, width = 800, height = 200)
    listbox.place(x = 0, y = 0)
    listbox.bind('<<ListboxSelect>>')
    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT)
    listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=listbox.yview)

    # ==== Buttons / Scans ====
    B11 = customtkinter.CTkButton(work_frame, text = "Start Scan", command=startScan, width = 170)
    B11.place(x = 16, y = 500)
    B21 = customtkinter.CTkButton(work_frame, text = "Save Result", command=saveScan, width = 170)
    B21.place(x = 210, y = 500)




def hide_indicators():
    port_scanner_indicator.configure(bg_color='transparent')
    ping_indicator.configure(bg_color='transparent')
    traceroute_indicator.configure(bg_color='transparent')
    ip_block_indicator.configure(bg_color='transparent')
    snipper_indicator.configure(bg_color='transparent')
    last_indicator.configure(bg_color='transparent')

def repage():
    for frame in work_frame.winfo_children():
        frame.destroy()

def indicators(start,end,page):

    hide_indicators()
    repage()

    start.configure(bg_color='#564305')
    end.configure(bg_color='#564305')
    page()


    # ==== Feature Options UI ====
        
option_frame=customtkinter.CTkFrame(master=app_frame, width=800, height=100, corner_radius=5,border_color='#B3DEEC',border_width=1.3)

snipper_indicator=customtkinter.CTkLabel(option_frame,text='',width=10, bg_color='transparent')
snipper_indicator.pack(side=tk.LEFT, padx=5)

snippper_bt= customtkinter.CTkButton(master=option_frame, width=114,border_width=2 ,text="Network Analyzer", command=lambda: indicators(snipper_indicator,ping_indicator,snipper),corner_radius=6, fg_color='transparent', text_color='gold', border_color='gold' ,hover_color='#564305')
snippper_bt.pack(side=tk.LEFT, padx=10)

ping_indicator=customtkinter.CTkLabel(option_frame,text='',width=10, bg_color='transparent')
ping_indicator.pack(side=tk.LEFT, padx=5)

ping_bt= customtkinter.CTkButton(master=option_frame, width=114,border_width=2 ,text="Ping", command=lambda: indicators(ping_indicator,traceroute_indicator,ping_feature),corner_radius=6, fg_color='transparent', text_color='gold', border_color='gold' ,hover_color='#564305')
ping_bt.pack(side=tk.LEFT, padx=10)

traceroute_indicator=customtkinter.CTkLabel(option_frame,text='', width=10,bg_color='transparent')
traceroute_indicator.pack(side=tk.LEFT, padx=5)

traceroute_bt= customtkinter.CTkButton(master=option_frame, width=114, border_width=2 ,text="Traceroute", command=lambda: indicators(traceroute_indicator,ip_block_indicator,traceroute), corner_radius=6, fg_color='transparent', text_color='gold',border_color='gold', hover_color='#564305')
traceroute_bt.pack(side=tk.LEFT, padx=10)

ip_block_indicator=customtkinter.CTkLabel(option_frame,text='', width=10,bg_color='transparent')
ip_block_indicator.pack(side=tk.LEFT, padx=5)

ip_block_bt= customtkinter.CTkButton(master=option_frame, width=114,border_width=2 , text="IP_Blocker", command=lambda: indicators(ip_block_indicator,port_scanner_indicator,ip_block), corner_radius=6, fg_color='transparent',text_color='gold', border_color='gold', hover_color='#564305')
ip_block_bt.pack(side=tk.LEFT, padx=10)

port_scanner_indicator=customtkinter.CTkLabel(option_frame,text='', width=10,bg_color='transparent')
port_scanner_indicator.pack(side=tk.LEFT, padx=5)

port_scanner_bt= customtkinter.CTkButton(master=option_frame, width=114,border_width=2 , text="Port Scanner", command=lambda: indicators(port_scanner_indicator,last_indicator,port_scanner), corner_radius=6, fg_color='transparent',text_color='gold', border_color='gold', hover_color='#564305')
port_scanner_bt.pack(side=tk.LEFT, padx=10)

last_indicator=customtkinter.CTkLabel(option_frame,text='', width=10,bg_color='transparent')
last_indicator.pack(side=tk.LEFT, padx=5)

option_frame.pack(side=tk.TOP)
option_frame.pack_propagate(False)


    # ==== Main working UI ====

work_frame=customtkinter.CTkFrame(master=app_frame, width=800, height=600,corner_radius=5,border_color='#B3DEEC',border_width=2)
    
work_frame.pack(side=tk.BOTTOM)
work_frame.pack_propagate(False)


app_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)


app.mainloop()