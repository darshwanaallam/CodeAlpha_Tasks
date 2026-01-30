from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list

def analyze_packet(packet):
    print("Packet captured!")  # Debug: Confirms a packet was received
    print("="*60)

    # Check if packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        # Identify protocol
        if TCP in packet:
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif ICMP in packet:
            print("Protocol       : ICMP")

        else:
            print(f"Protocol       : Other ({protocol})")

        # Display payload if available
        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"Payload        : {payload.decode(errors='ignore')}")
            except:
                print(f"Payload (raw)  : {payload}")

    else:
        print("Non-IP packet captured")

def start_sniffing():
    print("Starting packet capture on your network...")
    print("Press CTRL+C to stop.\n")

    # List available interfaces
    interfaces = get_if_list()
    if not interfaces:
        print("No interfaces found. Ensure Npcap is installed and you're running as Administrator.")
        return

    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    
    # Prompt user to select an interface
    try:
        choice = int(input("Select an interface by number (e.g., 0 for the first): "))
        selected_iface = interfaces[choice]
    except (ValueError, IndexError):
        print("Invalid choice. Exiting.")
        return

    print(f"Using interface: {selected_iface}")
    print("Capturing up to 10 ICMP packets (e.g., pings). Generate traffic now!\n")

    # Sniff with filter for ICMP, count limit, and selected interface
    sniff(iface=selected_iface, filter="icmp", prn=analyze_packet, store=False, count=10)

if __name__ == "__main__":
    start_sniffing()