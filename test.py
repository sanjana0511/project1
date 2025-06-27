from scapy.all import sniff, IP, TCP, UDP
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from datetime import datetime
import argparse

# Set up logging
logging.basicConfig(
    filename='firewall_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Firewall rules (example: {protocol: {src_ip: {port: action}})
rules = {
    'TCP': {
        '192.168.1.100': {80: 'BLOCK'},
        '10.0.0.0/24': {22: 'ALLOW'}
    },
    'UDP': {
        '8.8.8.8': {53: 'ALLOW'}
    }
}

class FirewallGUI:
    def __init__(self, root):  # Fixed: Changed _init_ to __init__
        self.root = root
        self.root.title("Personal Firewall")
        self.root.geometry("600x400")
        
        # Packet display
        self.packet_display = scrolledtext.ScrolledText(root, height=15, width=70)
        self.packet_display.pack(pady=10)
        
        # Rule management
        self.rule_frame = ttk.LabelFrame(root, text="Add New Rule")
        self.rule_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(self.rule_frame, text="Protocol:").grid(row=0, column=0, padx=5)
        self.protocol_var = tk.StringVar(value="TCP")
        ttk.Combobox(self.rule_frame, textvariable=self.protocol_var, values=["TCP", "UDP"]).grid(row=0, column=1)
        
        ttk.Label(self.rule_frame, text="Source IP:").grid(row=1, column=0, padx=5)
        self.src_ip_entry = ttk.Entry(self.rule_frame)
        self.src_ip_entry.grid(row=1, column=1)
        
        ttk.Label(self.rule_frame, text="Port:").grid(row=2, column=0, padx=5)
        self.port_entry = ttk.Entry(self.rule_frame)
        self.port_entry.grid(row=2, column=1)
        
        ttk.Label(self.rule_frame, text="Action:").grid(row=3, column=0, padx=5)
        self.action_var = tk.StringVar(value="ALLOW")
        ttk.Combobox(self.rule_frame, textvariable=self.action_var, values=["ALLOW", "BLOCK"]).grid(row=3, column=1)
        
        ttk.Button(self.rule_frame, text="Add Rule", command=self.add_rule).grid(row=4, column=0, columnspan=2, pady=10)
        
        # Start/Stop button
        self.running = False
        self.start_stop_button = ttk.Button(root, text="Start Firewall", command=self.toggle_firewall)
        self.start_stop_button.pack(pady=10)
        
        self.packet_thread = None

    def add_rule(self):
        protocol = self.protocol_var.get().upper()
        src_ip = self.src_ip_entry.get()
        port = self.port_entry.get()
        action = self.action_var.get().upper()
        
        try:
            port = int(port)
            if protocol not in rules:
                rules[protocol] = {}
            if src_ip not in rules[protocol]:
                rules[protocol][src_ip] = {}
            rules[protocol][src_ip][port] = action
            logging.info(f"Added rule: {protocol} {src_ip}:{port} -> {action}")
            self.packet_display.insert(tk.END, f"Rule added: {protocol} {src_ip}:{port} -> {action}\n")
        except ValueError:
            self.packet_display.insert(tk.END, "Invalid port number\n")

    def toggle_firewall(self):
        if not self.running:
            self.running = True
            self.start_stop_button.config(text="Stop Firewall")
            self.packet_thread = threading.Thread(target=packet_sniffer, args=(self.packet_display,))
            self.packet_thread.daemon = True
            self.packet_thread.start()
        else:
            self.running = False
            self.start_stop_button.config(text="Start Firewall")
            # Note: Scapy's sniff() is harder to stop cleanly without signals; for simplicity, let thread run in background

def check_rule(packet):
    if IP not in packet:
        return "ALLOW"  # Non-IP packets are allowed by default
    
    src_ip = packet[IP].src
    protocol = None
    port = None
    
    if TCP in packet:
        protocol = 'TCP'
        port = packet[TCP].dport
    elif UDP in packet:
        protocol = 'UDP'
        port = packet[UDP].dport
    else:
        return "ALLOW"  # Non-TCP/UDP packets are allowed by default
    
    # Check rules
    if protocol in rules:
        for rule_ip, ports in rules[protocol].items():
            if src_ip.startswith(rule_ip.split('/')[0]):  # Basic subnet matching
                if port in ports:
                    return ports[port]
    return "ALLOW"

def packet_sniffer(display):
    def packet_callback(packet):
        action = check_rule(packet)
        log_msg = f"Packet: {packet.summary()} | Action: {action}"
        logging.info(log_msg)
        display.insert(tk.END, f"{datetime.now()}: {log_msg}\n")
        display.see(tk.END)
        
        # For BLOCK action, we could drop packets using iptables or kernel-level integration
        # For simplicity, we're only logging the action here
        if action == "BLOCK":
            display.insert(tk.END, f"Blocked packet from {packet[IP].src}:{packet[TCP].dport if TCP in packet else packet[UDP].dport}\n")
    
    try:
        # Sniff packets (requires root/admin privileges on some systems and Npcap on Windows)
        sniff(prn=packet_callback, store=False, filter="ip")
    except PermissionError:
        display.insert(tk.END, "Error: Packet sniffing requires root/admin privileges\n")
        logging.error("Packet sniffing requires root/admin privileges")

def main():
    parser = argparse.ArgumentParser(description="Personal Firewall")
    parser.add_argument('--no-gui', action='store_true', help="Run in CLI mode without GUI")
    args = parser.parse_args()
    
    if args.no_gui:
        # CLI mode
        logging.info("Starting firewall in CLI mode")
        packet_sniffer(scrolledtext.ScrolledText())  # Dummy display for CLI
    else:
        # GUI mode
        root = tk.Tk()
        app = FirewallGUI(root)
        root.mainloop()

if __name__ == "__main__":  # Fixed: Corrected _main_ to __main__
    main()