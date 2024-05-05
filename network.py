from scapy.all import *

# Define the filename for the PCAP file
pcap_file = "captured_packets.pcap"

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        elif ICMP in packet:
            src_port = None
            dst_port = None
            protocol = "ICMP"
        
        src_mac = packet.src
        dst_mac = packet.dst

        print(f"Protocol: {protocol}")
        print(f"Source IP: {src_ip}, Source MAC: {src_mac}, Source Port: {src_port}")
        print(f"Destination IP: {dst_ip}, Destination MAC: {dst_mac}, Destination Port: {dst_port}")
        
        if Raw in packet:
            data = packet[Raw].load
            print("Data:", data.hex())  # Print data in hexadecimal
        
        print("\n")
        print("##########################################\n")
        time.sleep(1)
        # Append the packet to the PCAP file
        wrpcap(pcap_file, packet, append=True)

    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        src_mac = packet[ARP].hwsrc
        dst_mac = packet[ARP].hwdst
        operation = "Request" if packet[ARP].op == 1 else "Reply"

        print("ARP Packet:")
        print(f"Operation: {operation}")
        print(f"Source IP: {src_ip}, Source MAC: {src_mac}")
        print(f"Destination IP: {dst_ip}, Destination MAC: {dst_mac}")
        
        print("\n")
    
        print("##########################################\n")
        time.sleep(1)
        # Append the packet to the PCAP file
        wrpcap(pcap_file, packet, append=True)

# Start sniffing and capture packets
sniff(prn=packet_callback, store=0)