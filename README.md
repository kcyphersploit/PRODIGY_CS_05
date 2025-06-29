# PRODIGY_CS_05
 Repository Maintained for Projects @ Prodigy Infotech

NetProbe: Network Packet Analyzer

Overview

NetProbe is a powerful Python script designed to function as a network packet analyzer or sniffer. It leverages the Scapy library to capture and inspect network traffic flowing through your selected interface.

Features

Cross-Protocol Analysis: Deciphers packets across various protocols, including TCP (Transmission Control Protocol), UDP (User Datagram Protocol), and ICMP (Internet Control Message Protocol).
Detailed Packet Information: Provides comprehensive details for each captured packet, encompassing source and destination IP addresses, ports, protocols, and payload data (both in hexadecimal and decoded formats, if possible).
User-Friendly Interface Selection: Guides you through the selection of your network interface for capturing packets.
Optional Service Protocol Filtering: Offers the option to filter captured packets based on a specific service protocol (TCP, UDP, or ICMP) for a more focused analysis.
Customizable Packet Capture: Allows you to specify the number of packets to capture (enter 0 for continuous capture; press Ctrl+C to exit).
Clear Output Formatting: Presents captured packet information in a well-organized and visually appealing format using color coding for better readability.
Requirements

Python 3 (https://www.python.org/downloads/)
Scapy Library (https://scapy.readthedocs.io/en/latest/) - Installation: pip install scapy
Important Note
