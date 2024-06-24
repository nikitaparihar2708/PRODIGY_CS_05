import scapy.all as scapy

def process_packet(packet):
    if packet.haslayer(scapy.Raw):
        raw_data = packet[scapy.Raw].load
        print(f"Payload : \n{raw_data}\n")
    else:
        print(packet.summary())

def sniff():
    print("Capturing packets at the 'Wi-Fi' interface.\n")
    scapy.sniff( iface = "Wi-Fi", prn = process_packet)
    

sniff()