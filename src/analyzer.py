# analyzer.py
from scapy.all import rdpcap, TCP, UDP, ICMP, IP, ARP
import pandas as pd
from collections import Counter

def load_pcap(file_path):
    try:
        packets = rdpcap(file_path)
        print(f"Loaded {len(packets)} packets from {file_path}")
        return packets
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return []

def parse_packets(packets):
    """Extract packet info and detect all protocols."""
    data = []
    protocol_counter = Counter()
    main_protocol_counter = Counter()
    ip_traffic_counter = Counter()

    for pkt in packets:
        try:
            src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[ARP].psrc if pkt.haslayer(ARP) else "")
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[ARP].pdst if pkt.haslayer(ARP) else "")
            length = len(pkt)
            timestamp = pkt.time
            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None)
            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)

            # Detect layers
            layers = []
            current_layer = pkt
            while current_layer:
                layers.append(current_layer.name)
                if not hasattr(current_layer, "payload") or current_layer.payload is None:
                    break
                current_layer = current_layer.payload

            full_protocol = " -> ".join(layers)
            main_protocol = layers[-1] if layers else "UNKNOWN"

            data.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "main_protocol": main_protocol,
                "full_protocol": full_protocol,
                "length": length
            })

            protocol_counter[full_protocol] += 1
            main_protocol_counter[main_protocol] += 1
            if src_ip:
                ip_traffic_counter[src_ip] += length
            if dst_ip:
                ip_traffic_counter[dst_ip] += length

        except Exception as e:
            print(f"Skipping packet due to error: {e}")

    df = pd.DataFrame(data)
    return df, protocol_counter, main_protocol_counter, ip_traffic_counter

def detect_suspicious(ip_traffic_counter, threshold=1048576, adaptive=False, factor=2):
    """
    Detect suspicious IPs based on traffic volume.
    
    Parameters:
    - ip_traffic_counter: Counter of bytes per IP
    - threshold: static threshold in bytes (default 1 MB)
    - adaptive: if True, compute threshold based on average traffic
    - factor: multiplier for average if adaptive is True
    """
    suspicious_ips = []

    if adaptive:
        # Compute average traffic per IP
        if not ip_traffic_counter:
            return []
        avg_traffic = sum(ip_traffic_counter.values()) / len(ip_traffic_counter)
        adaptive_threshold = avg_traffic * factor
        # print(f"Adaptive threshold: {adaptive_threshold} bytes")  # Optional debug
        for ip, total_bytes in ip_traffic_counter.items():
            if total_bytes > adaptive_threshold:
                suspicious_ips.append(ip)
    else:
        # Static threshold
        for ip, total_bytes in ip_traffic_counter.items():
            if total_bytes > threshold:
                suspicious_ips.append(ip)

    return suspicious_ips
