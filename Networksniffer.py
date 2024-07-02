from scapy.all import sniff, Ether, IP, TCP, UDP

# Packet callback function
def packet_callback(packet):
    if packet.haslayer(Ether):
        print("Ethernet Frame:")
        print(f"  Source MAC: {packet[Ether].src}")
        print(f"  Destination MAC: {packet[Ether].dst}")

    if packet.haslayer(IP):
        print("\nIP Packet:")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  Protocol: {packet[IP].proto}")

        # Check for TCP packets
        if packet.haslayer(TCP):
            print("\nTCP Segment:")
            print(f"  Source Port: {packet[TCP].sport}")
            print(f"  Destination Port: {packet[TCP].dport}")

        # Check for UDP packets
        elif packet.haslayer(UDP):
            print("\nUDP Datagram:")
            print(f"  Source Port: {packet[UDP].sport}")
            print(f"  Destination Port: {packet[UDP].dport}")

# Start sniffing
print("Starting network sniffer...")
sniff(prn=packet_callback, store=0)