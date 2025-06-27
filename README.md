# project1

## 🔰 Introduction

The **Personal Firewall** project is designed to monitor and control incoming and outgoing network traffic based on predefined rules. Built using Python and Scapy, this lightweight firewall application enables users to define rules that block or allow traffic based on IP address, port number, and protocol type. It also includes a GUI (optional) using Tkinter for ease of interaction and live monitoring of packet activity.



## 📄 Abstract

This project presents a software-based personal firewall that allows users to define custom rule sets for managing network traffic. It leverages the power of **Scapy** for packet sniffing and inspection and uses **Tkinter** for an interactive GUI. It supports rule customization (BLOCK/ALLOW) based on IP, protocol, and port, and maintains a log of all monitored activity. The tool can be used for educational, testing, or lightweight monitoring purposes, especially on Linux environments.



## 🛠️ Tools Used

| Tool                    | Purpose                                  |
| ----------------------- | ---------------------------------------- |
| **Python**              | Core programming language                |
| **Scapy**               | Sniffing and analyzing network packets   |
| **Tkinter**             | (Optional) GUI for live packet display   |
| **Logging**             | Tracks firewall events in log file       |
| **iptables** (Optional) | Enforcing OS-level blocking (Linux only) |



## 🧱 Steps Involved in Building the Project

1. **Packet Sniffing Setup:**

   * Used `scapy.sniff()` to capture packets in real-time.
   * Applied a filter to inspect only IP-based traffic.

2. **Firewall Rule Logic:**

   * Implemented dictionaries to store rule sets for TCP/UDP protocols.
   * Supported matching based on:

     * Source IP addresses (exact or subnet)
     * Destination ports
     * Protocol types (TCP/UDP)
     * Rule action: ALLOW or BLOCK

3. **Rule Evaluation:**

   * For every sniffed packet, the system checks if it matches any rule.
   * If matched, appropriate action is logged, and optionally displayed in GUI.

4. **Logging:**

   * All packet activities and rule actions are recorded in `firewall_log.txt`.

5. **GUI Interface (Tkinter):**

   * Displays real-time packet summary and actions taken.
   * Allows adding new rules dynamically via dropdowns and entry fields.
   * Provides a Start/Stop button to control the packet capture process.

6. **Optional System Integration:**

   * Extendable with `iptables` commands (via `subprocess`) to enforce rules at OS level for actual packet dropping.

---

## ✅ Conclusion

This Personal Firewall demonstrates how software-level monitoring and filtering of network traffic can be implemented using Python. While it is lightweight and suitable for user-level control and learning, its modular architecture allows for easy upgrades—such as integrating OS-level blocking or real-time alerts. The use of Scapy and Tkinter makes the project both functional and educational, offering insights into cybersecurity and network behavior.


