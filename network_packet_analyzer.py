from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"
        payload = packet.payload
        
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 50)

if __name__ == "__main__":
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)