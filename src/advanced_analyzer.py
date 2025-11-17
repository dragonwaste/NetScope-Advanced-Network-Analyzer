# advanced_analyzer.py

from scapy.all import TCP, UDP, ICMP, IP, ARP, DNS, Raw
from collections import Counter, defaultdict
import re

# Service port mapping (expanded)
SERVICE_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client',
    69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
    135: 'MS-RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
    587: 'SMTP-Submit', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MS-SQL', 1521: 'Oracle-DB', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

def get_service_name(port, protocol=None):
    """Map port number to service name"""
    if port in SERVICE_PORTS:
        return SERVICE_PORTS[port]
    return f"Port-{port}"


def analyze_connections(packets):
    """Advanced connection tracking with TCP state analysis"""
    connections = defaultdict(lambda: {
        'packets': 0,
        'bytes': 0,
        'syn_count': 0,
        'syn_ack_count': 0,
        'ack_count': 0,
        'fin_count': 0,
        'rst_count': 0,
        'first_seen': None,
        'last_seen': None,
        'complete_handshake': False
    })
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            
            conn_key = (src, sport, dst, dport)
            conn = connections[conn_key]
            
            # Update connection stats
            conn['packets'] += 1
            conn['bytes'] += len(pkt)
            
            if conn['first_seen'] is None:
                conn['first_seen'] = pkt.time
            conn['last_seen'] = pkt.time
            
            # Analyze TCP flags
            flags = pkt[TCP].flags
            if flags & 0x02:  # SYN
                conn['syn_count'] += 1
            if flags & 0x12:  # SYN-ACK
                conn['syn_ack_count'] += 1
            if flags & 0x10:  # ACK
                conn['ack_count'] += 1
            if flags & 0x01:  # FIN
                conn['fin_count'] += 1
            if flags & 0x04:  # RST
                conn['rst_count'] += 1
            
            # Check for complete handshake
            if conn['syn_count'] > 0 and conn['syn_ack_count'] > 0 and conn['ack_count'] > 0:
                conn['complete_handshake'] = True
    
    return connections


def detect_port_scanning(packets, threshold=10):
    """Detect potential port scanning activity"""
    # Track unique ports per source IP
    ip_ports = defaultdict(set)
    
    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            if pkt.haslayer(TCP):
                ip_ports[src].add(('TCP', pkt[TCP].dport))
            elif pkt.haslayer(UDP):
                ip_ports[src].add(('UDP', pkt[UDP].dport))
    
    # Identify scanners
    scanners = {}
    for ip, ports in ip_ports.items():
        if len(ports) >= threshold:
            scanners[ip] = {
                'port_count': len(ports),
                'ports': sorted(list(ports), key=lambda x: x[1])[:20]  # First 20 ports
            }
    
    return scanners


def detect_syn_flood(connections, threshold=50):
    """Detect potential SYN flood attacks (incomplete handshakes)"""
    incomplete_connections = []
    
    for conn_key, conn_data in connections.items():
        # SYN sent but no complete handshake
        if conn_data['syn_count'] > 0 and not conn_data['complete_handshake']:
            incomplete_connections.append({
                'src_ip': conn_key[0],
                'src_port': conn_key[1],
                'dst_ip': conn_key[2],
                'dst_port': conn_key[3],
                'syn_count': conn_data['syn_count']
            })
    
    # Group by destination IP
    target_syn_counts = defaultdict(int)
    for conn in incomplete_connections:
        target_syn_counts[conn['dst_ip']] += conn['syn_count']
    
    # Identify targets with high incomplete connections
    potential_targets = {
        ip: count for ip, count in target_syn_counts.items() 
        if count >= threshold
    }
    
    return potential_targets, incomplete_connections


def detect_icmp_flood(packets, threshold=100):
    """Detect ICMP flood attacks"""
    icmp_counter = Counter()
    
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            src = pkt[IP].src
            icmp_counter[src] += 1
    
    # Identify sources with high ICMP traffic
    icmp_flooders = {
        ip: count for ip, count in icmp_counter.items() 
        if count >= threshold
    }
    
    return icmp_flooders


def detect_dns_anomalies(packets):
    """Detect DNS tunneling and suspicious DNS activity"""
    dns_queries = []
    suspicious_dns = []
    
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            if pkt[DNS].qr == 0:  # DNS query
                query_name = pkt[DNS].qd.qname.decode('utf-8') if pkt[DNS].qd else ''
                
                dns_queries.append({
                    'src_ip': pkt[IP].src,
                    'query': query_name,
                    'length': len(query_name)
                })
                
                # Check for suspiciously long domain names (potential tunneling)
                if len(query_name) > 50:
                    suspicious_dns.append({
                        'src_ip': pkt[IP].src,
                        'query': query_name,
                        'reason': 'Unusually long domain name (potential DNS tunneling)'
                    })
    
    # Count queries per IP
    query_counter = Counter([q['src_ip'] for q in dns_queries])
    
    # High frequency DNS queries from single source
    high_freq_dns = {
        ip: count for ip, count in query_counter.items() 
        if count > 100
    }
    
    return dns_queries, suspicious_dns, high_freq_dns


def extract_http_info(packets):
    """Extract HTTP requests and responses"""
    http_requests = []
    http_responses = []
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Check for HTTP request
                if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                    lines = payload_str.split('\r\n')
                    method_line = lines[0].split()
                    
                    if len(method_line) >= 3:
                        http_requests.append({
                            'src_ip': pkt[IP].src if pkt.haslayer(IP) else '',
                            'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else '',
                            'method': method_line[0],
                            'url': method_line[1],
                            'version': method_line[2],
                            'timestamp': pkt.time
                        })
                
                # Check for HTTP response
                elif payload_str.startswith('HTTP/'):
                    lines = payload_str.split('\r\n')
                    status_line = lines[0].split()
                    
                    if len(status_line) >= 2:
                        http_responses.append({
                            'src_ip': pkt[IP].src if pkt.haslayer(IP) else '',
                            'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else '',
                            'status_code': status_line[1],
                            'timestamp': pkt.time
                        })
            except:
                pass
    
    return http_requests, http_responses


def detect_unusual_protocols(protocol_counter, whitelist=None):
    """Detect unusual or potentially dangerous protocols"""
    if whitelist is None:
        whitelist = ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'HTTP', 'HTTPS', 'Raw', 'Padding']
    
    unusual = {}
    for proto, count in protocol_counter.items():
        if proto not in whitelist:
            unusual[proto] = count
    
    return unusual


def analyze_packet_timing(df, interval_seconds=1):
    """Analyze packet timing to detect traffic spikes"""
    if df.empty or 'timestamp' not in df.columns:
        return []
    
    import pandas as pd
    
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    df['interval'] = df['datetime'].dt.floor(f'{interval_seconds}s')
    
    # Group by interval
    timeline = df.groupby('interval').agg({
        'length': ['count', 'sum']
    }).reset_index()
    
    timeline.columns = ['time', 'packets', 'bytes']
    
    # Calculate average and detect spikes
    avg_packets = timeline['packets'].mean()
    std_packets = timeline['packets'].std()
    
    # Spike = more than 3 standard deviations above mean
    timeline['is_spike'] = timeline['packets'] > (avg_packets + 3 * std_packets)
    
    spikes = timeline[timeline['is_spike']].to_dict('records')
    
    return timeline.to_dict('records'), spikes


def get_protocol_statistics(df):
    """Calculate detailed protocol statistics"""
    if df.empty:
        return {}
    
    protocol_stats = {}
    
    for protocol in df['main_protocol'].unique():
        protocol_df = df[df['main_protocol'] == protocol]
        protocol_stats[protocol] = {
            'count': len(protocol_df),
            'total_bytes': protocol_df['length'].sum(),
            'avg_packet_size': protocol_df['length'].mean(),
            'min_packet_size': protocol_df['length'].min(),
            'max_packet_size': protocol_df['length'].max(),
            'std_packet_size': protocol_df['length'].std()
        }
    
    return protocol_stats


def comprehensive_security_scan(packets, df, ip_traffic_counter):
    """Run all security detection algorithms"""
    print("   🔍 Analyzing connections...")
    connections = analyze_connections(packets)
    
    print("   🔍 Detecting port scans...")
    port_scanners = detect_port_scanning(packets, threshold=10)
    
    print("   🔍 Detecting SYN floods...")
    syn_flood_targets, incomplete_conns = detect_syn_flood(connections, threshold=20)
    
    print("   🔍 Detecting ICMP floods...")
    icmp_flooders = detect_icmp_flood(packets, threshold=50)
    
    print("   🔍 Analyzing DNS traffic...")
    dns_queries, suspicious_dns, high_freq_dns = detect_dns_anomalies(packets)
    
    print("   🔍 Extracting HTTP information...")
    http_requests, http_responses = extract_http_info(packets)
    
    return {
        'connections': connections,
        'port_scanners': port_scanners,
        'syn_flood_targets': syn_flood_targets,
        'incomplete_connections': incomplete_conns,
        'icmp_flooders': icmp_flooders,
        'dns_queries': dns_queries,
        'suspicious_dns': suspicious_dns,
        'high_freq_dns': high_freq_dns,
        'http_requests': http_requests,
        'http_responses': http_responses
    }