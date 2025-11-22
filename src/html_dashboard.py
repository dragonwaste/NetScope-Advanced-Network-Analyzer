# html_dashboard.py - Futuristic Cyberpunk Edition

import os
import json
from datetime import datetime

def create_dashboard(df, main_proto_counter, full_proto_counter, ip_traffic_counter, 
                    suspicious_ips, pcap_file, output_dir="reports"):
    """Generate a futuristic cyberpunk-style HTML dashboard"""
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Calculate statistics
    total_packets = len(df)
    total_bytes = df['length'].sum() if not df.empty else 0
    total_mb = total_bytes / 1024 / 1024
    unique_src_ips = df['src_ip'].nunique() if not df.empty else 0
    unique_dst_ips = df['dst_ip'].nunique() if not df.empty else 0
    
    # Get timestamp range
    if not df.empty and 'timestamp' in df.columns:
        try:
            min_time = float(df['timestamp'].min())
            max_time = float(df['timestamp'].max())
            start_time = datetime.fromtimestamp(min_time).strftime('%Y-%m-%d %H:%M:%S')
            end_time = datetime.fromtimestamp(max_time).strftime('%Y-%m-%d %H:%M:%S')
            duration = max_time - min_time
        except:
            start_time, end_time, duration = "N/A", "N/A", 0
    else:
        start_time, end_time, duration = "N/A", "N/A", 0
    
    # Generate charts
    protocol_chart = generate_protocol_pie_chart(main_proto_counter)
    top_talkers_chart = generate_top_talkers_chart(ip_traffic_counter)
    packet_size_chart = generate_packet_size_chart(df)
    protocol_bar_chart = generate_protocol_bar_chart(main_proto_counter)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScope // Cyber Analysis Terminal</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Rajdhani:wght@300;400;500;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        :root {{
            --primary: #00f0ff;
            --secondary: #ff00ff;
            --accent: #00ff88;
            --warning: #ffaa00;
            --danger: #ff0055;
            --dark: #0a0a0f;
            --darker: #050508;
            --card-bg: rgba(10, 15, 25, 0.85);
            --border-glow: rgba(0, 240, 255, 0.3);
            --text: #e0e0e0;
            --text-dim: #6a7a8a;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Rajdhani', sans-serif;
            background: var(--darker);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }}
        
        /* Animated Background */
        .cyber-bg {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background: 
                linear-gradient(180deg, var(--darker) 0%, #0a0a1a 50%, var(--darker) 100%);
        }}
        
        .cyber-bg::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                repeating-linear-gradient(
                    0deg,
                    transparent,
                    transparent 2px,
                    rgba(0, 240, 255, 0.03) 2px,
                    rgba(0, 240, 255, 0.03) 4px
                );
            pointer-events: none;
            animation: scanlines 8s linear infinite;
        }}
        
        @keyframes scanlines {{
            0% {{ transform: translateY(0); }}
            100% {{ transform: translateY(100px); }}
        }}
        
        .cyber-bg::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(ellipse at 50% 0%, rgba(0, 240, 255, 0.1) 0%, transparent 60%);
            pointer-events: none;
        }}
        
        /* Grid Lines Background */
        .grid-overlay {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(0, 240, 255, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 240, 255, 0.05) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            animation: gridMove 20s linear infinite;
        }}
        
        @keyframes gridMove {{
            0% {{ transform: perspective(500px) rotateX(60deg) translateY(0); }}
            100% {{ transform: perspective(500px) rotateX(60deg) translateY(50px); }}
        }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
        }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, rgba(0, 240, 255, 0.1) 0%, rgba(255, 0, 255, 0.1) 100%);
            border: 1px solid var(--border-glow);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(20px);
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: conic-gradient(from 0deg, transparent, var(--primary), transparent, var(--secondary), transparent);
            animation: rotate 10s linear infinite;
            opacity: 0.1;
        }}
        
        @keyframes rotate {{
            100% {{ transform: rotate(360deg); }}
        }}
        
        .header-content {{
            position: relative;
            z-index: 1;
        }}
        
        .logo {{
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 25px;
        }}
        
        .logo-icon {{
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            box-shadow: 
                0 0 30px rgba(0, 240, 255, 0.5),
                0 0 60px rgba(255, 0, 255, 0.3),
                inset 0 0 30px rgba(255, 255, 255, 0.1);
            animation: pulse-glow 2s ease-in-out infinite;
        }}
        
        @keyframes pulse-glow {{
            0%, 100% {{ box-shadow: 0 0 30px rgba(0, 240, 255, 0.5), 0 0 60px rgba(255, 0, 255, 0.3); }}
            50% {{ box-shadow: 0 0 50px rgba(0, 240, 255, 0.8), 0 0 100px rgba(255, 0, 255, 0.5); }}
        }}
        
        .logo h1 {{
            font-family: 'Orbitron', sans-serif;
            font-size: 48px;
            font-weight: 900;
            background: linear-gradient(90deg, var(--primary), var(--secondary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 30px rgba(0, 240, 255, 0.5);
            letter-spacing: 4px;
        }}
        
        .tagline {{
            font-family: 'Share Tech Mono', monospace;
            color: var(--primary);
            font-size: 14px;
            letter-spacing: 3px;
            text-transform: uppercase;
            opacity: 0.8;
        }}
        
        .status-bar {{
            display: flex;
            gap: 40px;
            flex-wrap: wrap;
            margin-top: 30px;
            padding-top: 25px;
            border-top: 1px solid rgba(0, 240, 255, 0.2);
        }}
        
        .status-item {{
            display: flex;
            flex-direction: column;
            gap: 5px;
        }}
        
        .status-label {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .status-value {{
            font-family: 'Orbitron', sans-serif;
            font-size: 16px;
            color: var(--primary);
            text-shadow: 0 0 10px var(--primary);
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 15px;
            padding: 25px;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: var(--primary);
            box-shadow: 
                0 10px 40px rgba(0, 240, 255, 0.2),
                0 0 20px rgba(0, 240, 255, 0.1);
        }}
        
        .stat-icon {{
            font-size: 32px;
            margin-bottom: 15px;
            filter: drop-shadow(0 0 10px var(--primary));
        }}
        
        .stat-label {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 11px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 8px;
        }}
        
        .stat-value {{
            font-family: 'Orbitron', sans-serif;
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .stat-subvalue {{
            font-size: 12px;
            color: var(--text-dim);
            margin-top: 5px;
        }}
        
        /* Section Styling */
        .section {{
            margin-bottom: 30px;
        }}
        
        .section-title {{
            font-family: 'Orbitron', sans-serif;
            font-size: 20px;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .section-title::before {{
            content: '';
            width: 4px;
            height: 25px;
            background: linear-gradient(180deg, var(--primary), var(--secondary));
            border-radius: 2px;
            box-shadow: 0 0 10px var(--primary);
        }}
        
        .section-title::after {{
            content: '';
            flex: 1;
            height: 1px;
            background: linear-gradient(90deg, var(--primary), transparent);
        }}
        
        /* Charts Grid */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }}
        
        .chart-container {{
            background: var(--card-bg);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
        }}
        
        .chart-container::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--secondary), var(--accent));
        }}
        
        .chart-title {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 14px;
            color: var(--primary);
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 2px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .chart-title::before {{
            content: '>';
            color: var(--accent);
            animation: blink 1s infinite;
        }}
        
        @keyframes blink {{
            0%, 50% {{ opacity: 1; }}
            51%, 100% {{ opacity: 0; }}
        }}
        
        /* Alert Box */
        .alert-box {{
            background: var(--card-bg);
            border: 1px solid rgba(255, 0, 85, 0.3);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
        }}
        
        .alert-box::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--danger), var(--warning));
            animation: alert-pulse 2s ease-in-out infinite;
        }}
        
        @keyframes alert-pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        
        .alert-item {{
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 15px;
            background: rgba(255, 0, 85, 0.1);
            border: 1px solid rgba(255, 0, 85, 0.3);
            border-radius: 10px;
            margin-bottom: 12px;
        }}
        
        .alert-item:last-child {{
            margin-bottom: 0;
        }}
        
        .alert-icon {{
            font-size: 24px;
            animation: pulse 1.5s ease-in-out infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); }}
            50% {{ transform: scale(1.1); }}
        }}
        
        .alert-text {{
            flex: 1;
        }}
        
        .alert-ip {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 16px;
            color: var(--danger);
            text-shadow: 0 0 10px var(--danger);
        }}
        
        .alert-details {{
            font-size: 12px;
            color: var(--text-dim);
            margin-top: 5px;
        }}
        
        .no-alerts {{
            text-align: center;
            padding: 40px;
            color: var(--accent);
        }}
        
        .no-alerts-icon {{
            font-size: 60px;
            margin-bottom: 15px;
            filter: drop-shadow(0 0 20px var(--accent));
        }}
        
        .no-alerts-text {{
            font-family: 'Orbitron', sans-serif;
            font-size: 18px;
            text-transform: uppercase;
            letter-spacing: 3px;
        }}
        
        /* Tables */
        .table-container {{
            background: var(--card-bg);
            border: 1px solid rgba(0, 240, 255, 0.2);
            border-radius: 15px;
            overflow: hidden;
            backdrop-filter: blur(10px);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        thead {{
            background: linear-gradient(90deg, rgba(0, 240, 255, 0.2), rgba(255, 0, 255, 0.2));
        }}
        
        th {{
            font-family: 'Orbitron', sans-serif;
            padding: 18px;
            text-align: left;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--primary);
            border-bottom: 1px solid var(--border-glow);
        }}
        
        td {{
            padding: 15px 18px;
            border-bottom: 1px solid rgba(0, 240, 255, 0.1);
            font-size: 14px;
            font-family: 'Share Tech Mono', monospace;
        }}
        
        tr:hover {{
            background: rgba(0, 240, 255, 0.05);
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        code {{
            background: rgba(0, 240, 255, 0.1);
            padding: 4px 8px;
            border-radius: 4px;
            color: var(--primary);
            font-family: 'Share Tech Mono', monospace;
        }}
        
        /* Footer */
        .footer {{
            background: linear-gradient(90deg, rgba(0, 240, 255, 0.1), rgba(255, 0, 255, 0.1));
            border: 1px solid var(--border-glow);
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            margin-top: 30px;
            backdrop-filter: blur(10px);
        }}
        
        .footer-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .footer-text {{
            font-family: 'Share Tech Mono', monospace;
            font-size: 12px;
            color: var(--text-dim);
            letter-spacing: 1px;
        }}
        
        .footer-badge {{
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            padding: 10px 20px;
            border-radius: 20px;
            font-family: 'Orbitron', sans-serif;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: var(--dark);
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
            .logo h1 {{
                font-size: 28px;
            }}
            .status-bar {{
                gap: 20px;
            }}
        }}
        
        /* Glitch Effect for Title */
        .glitch {{
            position: relative;
        }}
        
        .glitch::before,
        .glitch::after {{
            content: attr(data-text);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }}
        
        .glitch::before {{
            animation: glitch-1 2s infinite linear alternate-reverse;
            clip-path: polygon(0 0, 100% 0, 100% 35%, 0 35%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background: linear-gradient(90deg, var(--secondary), var(--primary));
        }}
        
        .glitch::after {{
            animation: glitch-2 3s infinite linear alternate-reverse;
            clip-path: polygon(0 65%, 100% 65%, 100% 100%, 0 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background: linear-gradient(90deg, var(--accent), var(--primary));
        }}
        
        @keyframes glitch-1 {{
            0% {{ transform: translateX(0); }}
            20% {{ transform: translateX(-2px); }}
            40% {{ transform: translateX(2px); }}
            60% {{ transform: translateX(-1px); }}
            80% {{ transform: translateX(1px); }}
            100% {{ transform: translateX(0); }}
        }}
        
        @keyframes glitch-2 {{
            0% {{ transform: translateX(0); }}
            20% {{ transform: translateX(2px); }}
            40% {{ transform: translateX(-2px); }}
            60% {{ transform: translateX(1px); }}
            80% {{ transform: translateX(-1px); }}
            100% {{ transform: translateX(0); }}
        }}
    </style>
</head>
<body>
    <div class="cyber-bg"></div>
    <div class="grid-overlay"></div>
    
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <div class="logo-icon">🌐</div>
                    <div>
                        <h1 class="glitch" data-text="NETSCOPE">NETSCOPE</h1>
                        <div class="tagline">// Advanced Network Analysis Terminal v2.0</div>
                    </div>
                </div>
                
                <div class="status-bar">
                    <div class="status-item">
                        <span class="status-label">Target File</span>
                        <span class="status-value">{pcap_file}</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">Analysis Time</span>
                        <span class="status-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">Capture Window</span>
                        <span class="status-value">{start_time} → {end_time}</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">Duration</span>
                        <span class="status-value">{format_duration(duration)}</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">Status</span>
                        <span class="status-value" style="color: var(--accent);">● ANALYSIS COMPLETE</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">📦</div>
                <div class="stat-label">Total Packets</div>
                <div class="stat-value">{total_packets:,}</div>
                <div class="stat-subvalue">Captured frames analyzed</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">💾</div>
                <div class="stat-label">Data Volume</div>
                <div class="stat-value">{total_mb:.2f} MB</div>
                <div class="stat-subvalue">{total_bytes:,} bytes processed</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">🔀</div>
                <div class="stat-label">Protocols</div>
                <div class="stat-value">{len(main_proto_counter)}</div>
                <div class="stat-subvalue">Unique types detected</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">📡</div>
                <div class="stat-label">Source Nodes</div>
                <div class="stat-value">{unique_src_ips}</div>
                <div class="stat-subvalue">Origin addresses</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">🎯</div>
                <div class="stat-label">Target Nodes</div>
                <div class="stat-value">{unique_dst_ips}</div>
                <div class="stat-subvalue">Destination addresses</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">⚡</div>
                <div class="stat-label">Threat Level</div>
                <div class="stat-value" style="{'color: var(--danger);' if suspicious_ips else 'color: var(--accent);'}">{len(suspicious_ips)} ALERT{'S' if len(suspicious_ips) != 1 else ''}</div>
                <div class="stat-subvalue">Security anomalies detected</div>
            </div>
        </div>
        
        <!-- Security Analysis -->
        <div class="section">
            <h2 class="section-title">🚨 Threat Analysis Matrix</h2>
            <div class="alert-box">
                {generate_security_alerts_html(suspicious_ips, ip_traffic_counter)}
            </div>
        </div>
        
        <!-- Protocol Charts -->
        <div class="section">
            <h2 class="section-title">📊 Protocol Distribution Analysis</h2>
            <div class="charts-grid">
                <div class="chart-container">
                    <h3 class="chart-title">Protocol Signature Map</h3>
                    <div id="protocolPieChart"></div>
                </div>
                <div class="chart-container">
                    <h3 class="chart-title">Protocol Frequency Analysis</h3>
                    <div id="protocolBarChart"></div>
                </div>
            </div>
        </div>
        
        <!-- Traffic Analysis -->
        <div class="section">
            <h2 class="section-title">👥 Network Node Analysis</h2>
            <div class="charts-grid">
                <div class="chart-container">
                    <h3 class="chart-title">Top Traffic Sources</h3>
                    <div id="topTalkersChart"></div>
                </div>
                <div class="chart-container">
                    <h3 class="chart-title">Packet Size Distribution</h3>
                    <div id="packetSizeChart"></div>
                </div>
            </div>
        </div>
        
        <!-- Traffic Table -->
        <div class="section">
            <h2 class="section-title">💬 Traffic Breakdown Matrix</h2>
            <div class="table-container">
                {generate_top_talkers_table(ip_traffic_counter)}
            </div>
        </div>
        
        <!-- Protocol Table -->
        <div class="section">
            <h2 class="section-title">🔍 Protocol Signature Database</h2>
            <div class="table-container">
                {generate_protocol_table(main_proto_counter, full_proto_counter, total_packets)}
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <div class="footer-content">
                <div class="footer-text">
                    NETSCOPE NETWORK ANALYZER // PYTHON + SCAPY + PLOTLY
                </div>
                <div class="footer-badge">
                    CYBER ANALYSIS v2.0
                </div>
            </div>
        </div>
    </div>
    
    <script>
        {protocol_chart}
        {top_talkers_chart}
        {packet_size_chart}
        {protocol_bar_chart}
    </script>
</body>
</html>
"""
    
    output_file = os.path.join(output_dir, "dashboard.html")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✓ Futuristic Dashboard created: {output_file}")
    return output_file


def format_duration(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


def generate_security_alerts_html(suspicious_ips, ip_traffic_counter):
    """Generate HTML for security alerts"""
    if not suspicious_ips:
        return '''
        <div class="no-alerts">
            <div class="no-alerts-icon">🛡️</div>
            <div class="no-alerts-text">System Secure // No Threats Detected</div>
            <div style="margin-top: 10px; color: var(--text-dim); font-size: 14px;">
                All network activity within normal parameters
            </div>
        </div>
        '''
    
    html = ""
    for ip in suspicious_ips:
        bytes_transferred = ip_traffic_counter.get(ip, 0)
        mb_transferred = bytes_transferred / 1024 / 1024
        html += f'''
        <div class="alert-item">
            <div class="alert-icon">⚠️</div>
            <div class="alert-text">
                <div class="alert-ip">{ip}</div>
                <div class="alert-details">
                    Anomalous traffic volume: {bytes_transferred:,} bytes ({mb_transferred:.2f} MB)
                </div>
            </div>
            <div style="font-family: 'Orbitron', sans-serif; font-size: 11px; color: var(--danger); text-transform: uppercase;">
                HIGH TRAFFIC
            </div>
        </div>
        '''
    return html


def generate_top_talkers_table(ip_traffic_counter):
    """Generate HTML table for top talkers"""
    top_talkers = ip_traffic_counter.most_common(20)
    
    html = '''
    <table>
        <thead>
            <tr>
                <th>Rank</th>
                <th>Node Address</th>
                <th>Bytes</th>
                <th>Volume (MB)</th>
                <th>Traffic %</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
    '''
    
    total_bytes = sum(ip_traffic_counter.values())
    
    for idx, (ip, bytes_val) in enumerate(top_talkers, 1):
        mb = bytes_val / 1024 / 1024
        percentage = (bytes_val / total_bytes * 100) if total_bytes > 0 else 0
        status_color = "var(--danger)" if percentage > 30 else "var(--warning)" if percentage > 15 else "var(--accent)"
        status_text = "HIGH" if percentage > 30 else "MEDIUM" if percentage > 15 else "NORMAL"
        
        html += f'''
        <tr>
            <td><strong style="color: var(--primary);">#{idx:02d}</strong></td>
            <td><code>{ip}</code></td>
            <td>{bytes_val:,}</td>
            <td>{mb:.2f}</td>
            <td>{percentage:.1f}%</td>
            <td style="color: {status_color}; font-family: 'Orbitron', sans-serif; font-size: 11px;">● {status_text}</td>
        </tr>
        '''
    
    html += '</tbody></table>'
    return html


def generate_protocol_table(main_proto_counter, full_proto_counter, total_packets):
    """Generate HTML table for protocol details"""
    html = '''
    <table>
        <thead>
            <tr>
                <th>Protocol</th>
                <th>Packet Count</th>
                <th>Distribution</th>
                <th>Layer Chain</th>
            </tr>
        </thead>
        <tbody>
    '''
    
    proto_chains = {}
    for chain, count in full_proto_counter.items():
        main = chain.split(' -> ')[-1] if ' -> ' in chain else chain
        if main not in proto_chains:
            proto_chains[main] = chain
    
    for proto, count in main_proto_counter.most_common():
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        sample_chain = proto_chains.get(proto, proto)
        html += f'''
        <tr>
            <td><strong style="color: var(--primary);">{proto}</strong></td>
            <td>{count:,}</td>
            <td>{percentage:.1f}%</td>
            <td><code style="font-size: 11px;">{sample_chain}</code></td>
        </tr>
        '''
    
    html += '</tbody></table>'
    return html


def generate_protocol_pie_chart(proto_counter):
    """Generate Plotly pie chart for protocols - Cyberpunk style"""
    protocols = list(proto_counter.keys())
    counts = list(proto_counter.values())
    
    chart_json = {
        'data': [{
            'labels': protocols,
            'values': counts,
            'type': 'pie',
            'hole': 0.5,
            'marker': {
                'colors': ['#00f0ff', '#ff00ff', '#00ff88', '#ffaa00', '#ff0055', '#8855ff', '#00ffcc', '#ff6600'],
                'line': {'color': '#0a0a0f', 'width': 2}
            },
            'textinfo': 'label+percent',
            'textfont': {'size': 11, 'family': 'Share Tech Mono', 'color': '#e0e0e0'},
            'hovertemplate': '<b>%{label}</b><br>Packets: %{value:,}<br>Share: %{percent}<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 10, 'b': 10, 'l': 10, 'r': 10},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'showlegend': True,
            'legend': {
                'orientation': 'v', 
                'x': 1, 
                'y': 0.5,
                'font': {'family': 'Share Tech Mono', 'size': 11, 'color': '#e0e0e0'}
            },
            'font': {'family': 'Share Tech Mono', 'color': '#e0e0e0'}
        }
    }
    
    return f"Plotly.newPlot('protocolPieChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"


def generate_protocol_bar_chart(proto_counter):
    """Generate Plotly bar chart for protocols - Cyberpunk style"""
    protocols = list(proto_counter.keys())
    counts = list(proto_counter.values())
    
    chart_json = {
        'data': [{
            'x': protocols,
            'y': counts,
            'type': 'bar',
            'marker': {
                'color': counts,
                'colorscale': [[0, '#00f0ff'], [0.5, '#ff00ff'], [1, '#00ff88']],
                'line': {'color': '#00f0ff', 'width': 1}
            },
            'text': counts,
            'textposition': 'outside',
            'textfont': {'family': 'Orbitron', 'size': 11, 'color': '#00f0ff'},
            'hovertemplate': '<b>%{x}</b><br>Packets: %{y:,}<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 30, 'b': 80, 'l': 60, 'r': 20},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'xaxis': {
                'title': {'text': 'Protocol', 'font': {'family': 'Share Tech Mono', 'color': '#6a7a8a'}},
                'tickangle': -45,
                'tickfont': {'family': 'Share Tech Mono', 'color': '#e0e0e0'},
                'gridcolor': 'rgba(0, 240, 255, 0.1)',
                'linecolor': 'rgba(0, 240, 255, 0.3)'
            },
            'yaxis': {
                'title': {'text': 'Packet Count', 'font': {'family': 'Share Tech Mono', 'color': '#6a7a8a'}},
                'tickfont': {'family': 'Share Tech Mono', 'color': '#e0e0e0'},
                'gridcolor': 'rgba(0, 240, 255, 0.1)',
                'linecolor': 'rgba(0, 240, 255, 0.3)'
            },
            'font': {'family': 'Share Tech Mono', 'color': '#e0e0e0'}
        }
    }
    
    return f"Plotly.newPlot('protocolBarChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"


def generate_top_talkers_chart(ip_traffic_counter):
    """Generate Plotly bar chart for top talkers - Cyberpunk style"""
    top_talkers = ip_traffic_counter.most_common(10)
    ips = [ip for ip, _ in top_talkers]
    mbs = [bytes_val / 1024 / 1024 for _, bytes_val in top_talkers]
    
    chart_json = {
        'data': [{
            'y': ips,
            'x': mbs,
            'type': 'bar',
            'orientation': 'h',
            'marker': {
                'color': mbs,
                'colorscale': [[0, '#00ff88'], [0.5, '#00f0ff'], [1, '#ff00ff']],
                'line': {'color': '#00f0ff', 'width': 1}
            },
            'text': [f"{mb:.2f} MB" for mb in mbs],
            'textposition': 'outside',
            'textfont': {'family': 'Orbitron', 'size': 10, 'color': '#00f0ff'},
            'hovertemplate': '<b>%{y}</b><br>%{x:.2f} MB<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 10, 'b': 40, 'l': 130, 'r': 70},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'xaxis': {
                'title': {'text': 'Data Volume (MB)', 'font': {'family': 'Share Tech Mono', 'color': '#6a7a8a'}},
                'tickfont': {'family': 'Share Tech Mono', 'color': '#e0e0e0'},
                'gridcolor': 'rgba(0, 240, 255, 0.1)',
                'linecolor': 'rgba(0, 240, 255, 0.3)'
            },
            'yaxis': {
                'tickfont': {'family': 'Share Tech Mono', 'size': 11, 'color': '#e0e0e0'},
                'autorange': 'reversed',
                'linecolor': 'rgba(0, 240, 255, 0.3)'
            },
            'font': {'family': 'Share Tech Mono', 'color': '#e0e0e0'}
        }
    }
    
    return f"Plotly.newPlot('topTalkersChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"


def generate_packet_size_chart(df):
    """Generate Plotly histogram for packet sizes - Cyberpunk style"""
    if df.empty or 'length' not in df.columns:
        return "// No packet size data"
    
    sizes = df['length'].tolist()
    
    chart_json = {
        'data': [{
            'x': sizes,
            'type': 'histogram',
            'nbinsx': 50,
            'marker': {
                'color': 'rgba(0, 240, 255, 0.7)',
                'line': {'color': '#00f0ff', 'width': 1}
            },
            'hovertemplate': 'Size: %{x} bytes<br>Count: %{y}<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 10, 'b': 60, 'l': 60, 'r': 20},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'xaxis': {
                'title': {'text': 'Packet Size (bytes)', 'font': {'family': 'Share Tech Mono', 'color': '#6a7a8a'}},
                'tickfont': {'family': 'Share Tech Mono', 'color': '#e0e0e0'},
                'gridcolor': 'rgba(0, 240, 255, 0.1)',
                'linecolor': 'rgba(0, 240, 255, 0.3)'
            },
            'yaxis': {
                'title': {'text': 'Frequency', 'font': {'family': 'Share Tech Mono', 'color': '#6a7a8a'}},
                'tickfont': {'family': 'Share Tech Mono', 'color': '#e0e0e0'},
                'gridcolor': 'rgba(0, 240, 255, 0.1)',
                'linecolor': 'rgba(0, 240, 255, 0.3)'
            },
            'bargap': 0.05,
            'font': {'family': 'Share Tech Mono', 'color': '#e0e0e0'}
        }
    }
    
    return f"Plotly.newPlot('packetSizeChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"
