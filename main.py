# main.py
import sys
import os
import json

# Add src to path so we can import from it
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from analyzer import load_pcap, parse_packets, detect_suspicious
from report_generator import display_summary, save_summary_file, save_packet_reports
from visualizer import generate_all_visualizations
from html_dashboard import create_dashboard


def load_config(config_file="config/settings.json"):
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        print(f"✓ Configuration loaded from {config_file}")
        return config
    except FileNotFoundError:
        print(f"⚠ Config file not found. Using defaults.")
        return get_default_config()
    except Exception as e:
        print(f"⚠ Error loading config: {e}. Using defaults.")
        return get_default_config()


def get_default_config():
    """Return default configuration"""
    return {
        "input": {
            "pcap_file": "traffic.pcap"
        },
        "output": {
            "base_directory": "output",
            "dashboards_dir": "output/dashboards",
            "visualizations_dir": "output/visualizations",
            "reports_dir": "output/reports",
            "exports_dir": "output/exports"
        },
        "thresholds": {
            "suspicious_bytes": 1048576,
            "use_adaptive_threshold": False,
            "adaptive_factor": 5
        },
        "display": {
            "top_talkers_count": 15,
            "show_terminal_summary": True
        }
    }


def main():
    print("\n" + "="*70)
    print("🌐 NetScope - Network Traffic Analyzer")
    print("="*70 + "\n")
    
    # Load configuration
    config = load_config()
    
    # Extract settings
    pcap_file = config['input']['pcap_file']
    output_dirs = config['output']
    thresholds = config['thresholds']
    display = config['display']
    
    # Create output directories
    for dir_path in output_dirs.values():
        os.makedirs(dir_path, exist_ok=True)
    
    # Load packets
    print(f"📂 Loading PCAP file: {pcap_file}")
    packets = load_pcap(pcap_file)
    if not packets:
        print("❌ Failed to load packets. Exiting.")
        return

    # Parse packets
    print("🔍 Parsing packets...")
    df, full_proto_counter, main_proto_counter, ip_traffic_counter = parse_packets(packets)
    
    if df.empty:
        print("❌ No packets to analyze. Exiting.")
        return

    # Detect suspicious IPs
    print("🚨 Detecting suspicious activity...")
    if thresholds['use_adaptive_threshold']:
        suspicious_ips = detect_suspicious(
            ip_traffic_counter,
            adaptive=True,
            factor=thresholds['adaptive_factor']
        )
        print(f"   Using adaptive threshold (factor: {thresholds['adaptive_factor']}x)")
    else:
        suspicious_ips = detect_suspicious(
            ip_traffic_counter,
            threshold=thresholds['suspicious_bytes']
        )
        print(f"   Using static threshold: {thresholds['suspicious_bytes']:,} bytes")

    # Display terminal summary
    if display['show_terminal_summary']:
        print("\n" + "="*70)
        print("📊 TERMINAL SUMMARY")
        print("="*70)
        display_summary(main_proto_counter, full_proto_counter, ip_traffic_counter, suspicious_ips)

    # Save text reports
    print("\n" + "="*70)
    print("💾 SAVING TEXT REPORTS")
    print("="*70)
    save_summary_file(
        main_proto_counter, full_proto_counter, 
        ip_traffic_counter, suspicious_ips, 
        folder=output_dirs['reports_dir']
    )
    save_packet_reports(df, folder=output_dirs['exports_dir'])

    # Generate individual visualizations
    print("\n" + "="*70)
    print("🎨 GENERATING VISUALIZATIONS")
    print("="*70)
    generate_all_visualizations(
        df, main_proto_counter, full_proto_counter, 
        ip_traffic_counter, 
        output_dir=output_dirs['visualizations_dir']
    )
    
    # Generate HTML Dashboard
    print("\n" + "="*70)
    print("🌟 GENERATING HTML DASHBOARD")
    print("="*70)
    dashboard_file = create_dashboard(
        df, main_proto_counter, full_proto_counter, 
        ip_traffic_counter, suspicious_ips, pcap_file, 
        output_dir=output_dirs['dashboards_dir']
    )
    
    print("\n" + "="*70)
    print("✅ ANALYSIS COMPLETE!")
    print("="*70)
    print(f"\n📊 Main Dashboard: {dashboard_file}")
    print(f"📁 All outputs saved in '{output_dirs['base_directory']}/' directory")
    print(f"\n📂 Output Structure:")
    print(f"   ├── {output_dirs['dashboards_dir']}/    → Main HTML dashboard")
    print(f"   ├── {output_dirs['visualizations_dir']}/ → Individual charts (HTML & PNG)")
    print(f"   ├── {output_dirs['reports_dir']}/       → Text summary reports")
    print(f"   └── {output_dirs['exports_dir']}/       → CSV and formatted data\n")


if __name__ == "__main__":
    main()