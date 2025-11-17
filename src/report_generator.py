# report_generator.py
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from tabulate import tabulate

console = Console()

# --------------------------
# Terminal Summary Function
# --------------------------
def display_summary(main_proto_counter, full_proto_counter, ip_traffic_counter, suspicious_ips):
    """Display a visually stunning terminal summary using Rich."""
    
    total_packets = sum(main_proto_counter.values())
    total_bytes = sum(ip_traffic_counter.values())

    # Header Panel
    console.print(Panel.fit(
        "[bold cyan]🌐 NETWORK TRAFFIC SUMMARY 🌐[/bold cyan]", 
        border_style="magenta"
    ))

    # Basic Stats
    console.print(f"\n[yellow]📦 Total Packets:[/yellow] {total_packets:,}")
    console.print(f"[yellow]💾 Total Bytes:[/yellow]   {total_bytes:,} ({total_bytes/1024/1024:.2f} MB)\n")

    # Main Protocol Table
    if main_proto_counter:
        table1 = Table(title="📊 Main Protocol Counts", header_style="bold green")
        table1.add_column("Protocol", style="cyan")
        table1.add_column("Count", justify="right", style="yellow")
        table1.add_column("Percentage", justify="right", style="magenta")
        
        for proto, count in main_proto_counter.most_common():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            table1.add_row(proto, f"{count:,}", f"{percentage:.1f}%")
        console.print(table1)

    # Full Protocol Chains (Top 10)
    if full_proto_counter:
        console.print("\n")
        table2 = Table(title="🔗 Full Protocol Chains (Top 10)", header_style="bold blue")
        table2.add_column("Protocol Chain", style="cyan")
        table2.add_column("Count", justify="right", style="yellow")
        
        for proto, count in full_proto_counter.most_common(10):
            table2.add_row(proto, f"{count:,}")
        console.print(table2)

    # Top Talkers Table
    console.print("\n")
    table3 = Table(title="👥 Top Talkers (by Bytes)", header_style="bold green")
    table3.add_column("IP Address", style="cyan")
    table3.add_column("Bytes Transferred", justify="right", style="yellow")
    table3.add_column("MB", justify="right", style="magenta")
    
    for ip, bytes_ in list(ip_traffic_counter.most_common(10)):
        table3.add_row(ip, f"{bytes_:,}", f"{bytes_/1024/1024:.2f}")
    console.print(table3)

    # Suspicious IPs
    console.print("\n")
    if suspicious_ips:
        console.print("[bold red]🚨 Suspicious IPs Detected (High Traffic):[/bold red]")
        for ip in suspicious_ips:
            bytes_transferred = ip_traffic_counter.get(ip, 0)
            console.print(f"  [red]⚠️  {ip} - {bytes_transferred:,} bytes ({bytes_transferred/1024/1024:.2f} MB)[/red]")
    else:
        console.print("[bold green]✅ No suspicious IPs detected 🎉[/bold green]")
    
    console.print("\n")


# --------------------------
# File Outputs
# --------------------------
def save_summary_file(main_proto_counter, full_proto_counter, ip_traffic_counter, suspicious_ips, folder="reports"):
    os.makedirs(folder, exist_ok=True)
    filename = os.path.join(folder, "summary_report.txt")

    total_packets = sum(main_proto_counter.values())
    total_bytes = sum(ip_traffic_counter.values())
    top_talkers = sorted(ip_traffic_counter.items(), key=lambda x: x[1], reverse=True)[:10]

    with open(filename, "w", encoding="utf-8") as f:
        f.write("="*70 + "\n")
        f.write("             NETWORK TRAFFIC ANALYZER REPORT             \n")
        f.write("="*70 + "\n\n")
        f.write(f"Total Packets:  {total_packets:,}\n")
        f.write(f"Total Bytes:    {total_bytes:,} ({total_bytes/1024/1024:.2f} MB)\n\n")
        
        f.write("Main Protocol Counts:\n")
        f.write(tabulate([[p, c] for p, c in main_proto_counter.items()],
                         headers=["Protocol", "Count"], tablefmt="grid"))
        f.write("\n\n")
        
        f.write("Full Protocol Chains Counts (Top 15):\n")
        f.write(tabulate([[p, c] for p, c in full_proto_counter.most_common(15)],
                         headers=["Protocol Chain", "Count"], tablefmt="grid"))
        f.write("\n\n")
        
        f.write("Top Talkers (by Bytes):\n")
        f.write(tabulate([[ip, f"{b:,}", f"{b/1024/1024:.2f}"] for ip, b in top_talkers],
                         headers=["IP Address", "Bytes Transferred", "MB"], tablefmt="grid"))
        f.write("\n\n")
        
        f.write("Suspicious IPs Detected:\n")
        if suspicious_ips:
            for ip in suspicious_ips:
                bytes_transferred = ip_traffic_counter.get(ip, 0)
                f.write(f"⚠️  {ip} - {bytes_transferred:,} bytes ({bytes_transferred/1024/1024:.2f} MB)\n")
        else:
            f.write("None\n")
        
        f.write("\n" + "="*70 + "\n")
        f.write("Report generated by Network Traffic Analyzer (Python)\n")
        f.write("="*70 + "\n")

    print(f"✓ Summary report saved to {filename}")


def save_packet_reports(df, folder="reports"):
    os.makedirs(folder, exist_ok=True)
    csv_filename = os.path.join(folder, "report.csv")
    txt_filename = os.path.join(folder, "file_formatted.txt")

    df.fillna("", inplace=True)

    # Save CSV
    df.to_csv(csv_filename, index=False)
    print(f"✓ CSV data saved to {csv_filename}")

    # Save formatted TXT
    with open(txt_filename, "w", encoding="utf-8") as f:
        f.write("="*70 + "\n")
        f.write("                NETWORK TRAFFIC DETAILED REPORT              \n")
        f.write("="*70 + "\n\n")
        f.write(tabulate(df.head(50), headers="keys", tablefmt="grid"))
        f.write(f"\n\n(Showing first 50 packets out of {len(df)} total)\n")
        f.write("="*70 + "\n")
    print(f"✓ Formatted packet report saved to {txt_filename}")