# create_sample_pcap.py
"""
Sample PCAP Generator for NetScope Traffic Analyzer
Run this to create demonstration traffic data.
"""

from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap
import random
import time

def create_sample_traffic():
    """Generate realistic sample network traffic"""
    packets = []
    
    print("🔨 Generating sample network traffic...\n")
    
    # Safe IP addresses (documentation/test ranges)
    local_ip = "192.168.1.100"
    gateway_ip = "192.168.1.1"
    dns_server = "8.8.8.8"
    web_servers = ["93.184.216.34", "151.101.1.140", "104.16.132.229"]
    
    base_time = time.time()
    
    # 1. ICMP packets (ping)
    print("   📡 Adding ICMP packets...")
    for i in range(10):
        pkt = Ether()/IP(src=local_ip, dst=gateway_ip)/ICMP()
        pkt.time = base_time + i * 0.1
        packets.append(pkt)
    
    # 2. DNS queries
    print("   🔍 Adding DNS queries...")
    domains = ["example.com", "google.com", "github.com", "wikipedia.org", "stackoverflow.com"]
    for i, domain in enumerate(domains):
        pkt = Ether()/IP(src=local_ip, dst=dns_server)/UDP(sport=random.randint(50000, 60000), dport=53)/DNS(qd=DNSQR(qname=domain))
        pkt.time = base_time + 1 + i * 0.2
        packets.append(pkt)
    
    # 3. HTTP traffic (web browsing)
    print("   🌐 Adding HTTP requests...")
    http_requests = [
        "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "GET /index.html HTTP/1.1\r\nHost: test.com\r\n\r\n",
        "POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 50\r\n\r\n",
        "GET /images/logo.png HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n"
    ]
    
    for i, request in enumerate(http_requests):
        dst_ip = random.choice(web_servers)
        sport = random.randint(50000, 60000)
        
        # TCP 3-way handshake
        syn = Ether()/IP(src=local_ip, dst=dst_ip)/TCP(sport=sport, dport=80, flags="S")
        syn.time = base_time + 2 + i * 0.5
        packets.append(syn)
        
        synack = Ether()/IP(src=dst_ip, dst=local_ip)/TCP(sport=80, dport=sport, flags="SA")
        synack.time = base_time + 2.05 + i * 0.5
        packets.append(synack)
        
        ack = Ether()/IP(src=local_ip, dst=dst_ip)/TCP(sport=sport, dport=80, flags="A")
        ack.time = base_time + 2.1 + i * 0.5
        packets.append(ack)
        
        # HTTP request
        http = Ether()/IP(src=local_ip, dst=dst_ip)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=request)
        http.time = base_time + 2.15 + i * 0.5
        packets.append(http)
    
    # 4. HTTPS connections
    print("   🔒 Adding HTTPS traffic...")
    for i in range(8):
        dst_ip = random.choice(web_servers)
        sport = random.randint(50000, 60000)
        
        syn = Ether()/IP(src=local_ip, dst=dst_ip)/TCP(sport=sport, dport=443, flags="S")
        syn.time = base_time + 4 + i * 0.3
        packets.append(syn)
        
        synack = Ether()/IP(src=dst_ip, dst=local_ip)/TCP(sport=443, dport=sport, flags="SA")
        synack.time = base_time + 4.05 + i * 0.3
        packets.append(synack)
    
    # 5. Bulk data transfer
    print("   📦 Adding data transfer packets...")
    dst_ip = web_servers[0]
    sport = random.randint(50000, 60000)
    for i in range(25):
        pkt = Ether()/IP(src=local_ip, dst=dst_ip)/TCP(sport=sport, dport=80, flags="A")/Raw(load="X" * 1400)
        pkt.time = base_time + 5 + i * 0.05
        packets.append(pkt)
    
    # 6. UDP traffic
    print("   🎯 Adding UDP packets...")
    for i in range(12):
        dst_ip = random.choice(web_servers)
        pkt = Ether()/IP(src=local_ip, dst=dst_ip)/UDP(sport=random.randint(50000, 60000), dport=random.randint(8000, 9000))/Raw(load="UDP_PAYLOAD_DATA")
        pkt.time = base_time + 6 + i * 0.15
        packets.append(pkt)
    
    # 7. Some suspicious-looking traffic (to test detection)
    print("   ⚠️  Adding high-volume traffic (for testing detection)...")
    suspicious_ip = "10.0.0.50"
    for i in range(30):
        pkt = Ether()/IP(src=suspicious_ip, dst=gateway_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        pkt.time = base_time + 7 + i * 0.02
        packets.append(pkt)
    
    print(f"\n✅ Generated {len(packets)} packets")
    return packets


def main():
    print("\n" + "="*70)
    print(" "*15 + "📡 Sample PCAP Generator for NetScope")
    print("="*70 + "\n")
    
    # Generate packets
    packets = create_sample_traffic()
    
    # Save to file
    output_file = "traffic.pcap"
    print(f"\n💾 Saving to '{output_file}'...")
    wrpcap(output_file, packets)
    
    print("\n" + "="*70)
    print("✅ SUCCESS! Sample PCAP created")
    print("="*70)
    print(f"\n📊 File created: {output_file}")
    print(f"📦 Total packets: {len(packets)}")
    print(f"\n🚀 Next step: Run the analyzer")
    print(f"   → python main.py\n")


if __name__ == "__main__":
    main()