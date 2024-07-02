# Basic-Network-Sniffer
This Python script is a simple network sniffer that captures and analyzes network traffic using the scapy library. 

Imports
from scapy.all import sniff, Ether, IP, TCP, UDP
This line imports necessary functions and classes from the scapy library:
sniff: Function to capture network packets.
Ether: Class to represent Ethernet frames.
IP: Class to represent IP packets.
TCP: Class to represent TCP segments.
UDP: Class to represent UDP datagrams.
Packet Callback Function

def packet_callback(packet):
Defines a callback function packet_callback that is called for each captured packet. The packet parameter represents the captured packet.

Ethernet Frame Analysis
if packet.haslayer(Ether):
        print("Ethernet Frame:")
        print(f"  Source MAC: {packet[Ether].src}")
        print(f"  Destination MAC: {packet[Ether].dst}")
if packet.haslayer(Ether): Checks if the packet contains an Ethernet frame.
print("Ethernet Frame:"): Prints a header indicating the packet is an Ethernet frame.
print(f" Source MAC: {packet[Ether].src}"): Prints the source MAC address.
print(f" Destination MAC: {packet[Ether].dst}"): Prints the destination MAC address.

IP Packet Analysis
if packet.haslayer(IP):
        print("\nIP Packet:")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  Protocol: {packet[IP].proto}")
if packet.haslayer(IP): Checks if the packet contains an IP layer.
print("\nIP Packet:"): Prints a header indicating the packet is an IP packet.
print(f" Source IP: {packet[IP].src}"): Prints the source IP address.
print(f" Destination IP: {packet[IP].dst}"): Prints the destination IP address.
print(f" Protocol: {packet[IP].proto}"): Prints the protocol used (e.g., TCP, UDP).

TCP Segment Analysis
if packet.haslayer(TCP):
            print("\nTCP Segment:")
            print(f"  Source Port: {packet[TCP].sport}")
            print(f"  Destination Port: {packet[TCP].dport}")
if packet.haslayer(TCP): Checks if the packet contains a TCP segment.
print("\nTCP Segment:"): Prints a header indicating the packet is a TCP segment.
print(f" Source Port: {packet[TCP].sport}"): Prints the source port.
print(f" Destination Port: {packet[TCP].dport}"): Prints the destination port.

UDP Datagram Analysis
elif packet.haslayer(UDP):
            print("\nUDP Datagram:")
            print(f"  Source Port: {packet[UDP].sport}")
            print(f"  Destination Port: {packet[UDP].dport}")
elif packet.haslayer(UDP): Checks if the packet contains a UDP datagram.
print("\nUDP Datagram:"): Prints a header indicating the packet is a UDP datagram.
print(f" Source Port: {packet[UDP].sport}"): Prints the source port.
print(f" Destination Port: {packet[UDP].dport}"): Prints the destination port.

Start Sniffing
print("Starting network sniffer...")
sniff(prn=packet_callback, store=0)
print("Starting network sniffer..."): Prints a message indicating the sniffer is starting.
sniff(prn=packet_callback, store=0): Starts sniffing packets. The sniff function:
prn=packet_callback: Sets the callback function to packet_callback which will be called for each captured packet.
store=0: Prevents storing packets in memory, which is useful to save memory when processing a large number of packets.
In summary, this script sets up a network sniffer that captures packets, analyzes their Ethernet, IP, TCP, and UDP layers, and prints relevant information about each captured packet to the console.
