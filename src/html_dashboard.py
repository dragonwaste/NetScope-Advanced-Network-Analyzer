# html_dashboard.py

import os
import json
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

def create_dashboard(df, main_proto_counter, full_proto_counter, ip_traffic_counter, 
                    suspicious_ips, pcap_file, output_dir="reports"):
    """Generate a beautiful, comprehensive HTML dashboard"""
    
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
            # Convert to float to handle Decimal objects from Scapy
            min_time = float(df['timestamp'].min())
            max_time = float(df['timestamp'].max())
            start_time = datetime.fromtimestamp(min_time).strftime('%Y-%m-%d %H:%M:%S')
            end_time = datetime.fromtimestamp(max_time).strftime('%Y-%m-%d %H:%M:%S')
            duration = max_time - min_time
        except:
            start_time = "N/A"
            end_time = "N/A"
            duration = 0
    else:
        start_time = "N/A"
        end_time = "N/A"
        duration = 0
    
    # Generate embedded charts
    protocol_chart = generate_protocol_pie_chart(main_proto_counter)
    top_talkers_chart = generate_top_talkers_chart(ip_traffic_counter)
    packet_size_chart = generate_packet_size_chart(df)
    protocol_bar_chart = generate_protocol_bar_chart(main_proto_counter)
    
    # Generate HTML
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScope - Network Traffic Analysis Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.98);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        /* Header Section */
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 50px;
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: pulse 15s ease-in-out infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ transform: scale(1); }}
            50% {{ transform: scale(1.1); }}
        }}
        
        .header-content {{
            position: relative;
            z-index: 1;
        }}
        
        .logo {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .logo-icon {{
            width: 60px;
            height: 60px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 30px;
            backdrop-filter: blur(10px);
        }}
        
        .logo h1 {{
            font-size: 42px;
            font-weight: 800;
            letter-spacing: -1px;
        }}
        
        .subtitle {{
            font-size: 18px;
            opacity: 0.9;
            font-weight: 300;
            margin-top: 10px;
        }}
        
        .analysis-info {{
            display: flex;
            gap: 40px;
            margin-top: 30px;
            flex-wrap: wrap;
        }}
        
        .info-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .info-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: 0.8;
            margin-bottom: 5px;
        }}
        
        .info-value {{
            font-size: 16px;
            font-weight: 600;
        }}
        
        /* Stats Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            padding: 40px 50px;
            background: #f8f9fa;
        }}
        
        .stat-card {{
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .stat-icon {{
            font-size: 36px;
            margin-bottom: 15px;
        }}
        
        .stat-label {{
            font-size: 13px;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
            margin-bottom: 10px;
        }}
        
        .stat-value {{
            font-size: 32px;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 5px;
        }}
        
        .stat-subvalue {{
            font-size: 14px;
            color: #718096;
        }}
        
        /* Content Section */
        .content {{
            padding: 40px 50px;
        }}
        
        .section {{
            margin-bottom: 50px;
        }}
        
        .section-title {{
            font-size: 24px;
            font-weight: 700;
            color: #2d3748;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title::before {{
            content: '';
            width: 4px;
            height: 30px;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
            border-radius: 2px;
        }}
        
        /* Charts */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        .chart-container {{
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
        }}
        
        .chart-title {{
            font-size: 18px;
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        /* Tables */
        .table-container {{
            background: white;
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
            overflow: hidden;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        
        th {{
            padding: 18px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        td {{
            padding: 16px 18px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 14px;
        }}
        
        tr:hover {{
            background: #f7fafc;
        }}
        
        tr:last-child td {{
            border-bottom: none;
        }}
        
        /* Security Alerts */
        .alert-box {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
            margin-bottom: 30px;
        }}
        
        .alert-item {{
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 15px;
            background: #fff5f5;
            border-left: 4px solid #e53e3e;
            border-radius: 8px;
            margin-bottom: 15px;
        }}
        
        .alert-item:last-child {{
            margin-bottom: 0;
        }}
        
        .alert-icon {{
            font-size: 24px;
        }}
        
        .alert-text {{
            flex: 1;
        }}
        
        .alert-ip {{
            font-weight: 600;
            color: #e53e3e;
        }}
        
        .alert-details {{
            font-size: 13px;
            color: #718096;
            margin-top: 5px;
        }}
        
        .no-alerts {{
            text-align: center;
            padding: 30px;
            color: #48bb78;
            font-size: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }}
        
        /* Footer */
        .footer {{
            background: #2d3748;
            color: white;
            padding: 30px 50px;
            text-align: center;
        }}
        
        .footer-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        
        .footer-text {{
            font-size: 14px;
            opacity: 0.8;
        }}
        
        .footer-badge {{
            background: rgba(255, 255, 255, 0.1);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .header, .content, .footer {{
                padding: 30px 25px;
            }}
        }}
        
        /* Animations */
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .stat-card, .chart-container, .table-container, .alert-box {{
            animation: fadeIn 0.6s ease-out backwards;
        }}
        
        .stat-card:nth-child(1) {{ animation-delay: 0.1s; }}
        .stat-card:nth-child(2) {{ animation-delay: 0.2s; }}
        .stat-card:nth-child(3) {{ animation-delay: 0.3s; }}
        .stat-card:nth-child(4) {{ animation-delay: 0.4s; }}
        .stat-card:nth-child(5) {{ animation-delay: 0.5s; }}
        .stat-card:nth-child(6) {{ animation-delay: 0.6s; }}
    </style>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <div class="logo-icon">🌐</div>
                    <div>
                        <h1>NetScope</h1>
                        <div class="subtitle">Advanced Network Traffic Analysis Platform</div>
                    </div>
                </div>
                
                <div class="analysis-info">
                    <div class="info-item">
                        <div class="info-label">PCAP File</div>
                        <div class="info-value">{pcap_file}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Analysis Date</div>
                        <div class="info-value">{datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Capture Period</div>
                        <div class="info-value">{start_time} → {end_time}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Duration</div>
                        <div class="info-value">{format_duration(duration)}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">📦</div>
                <div class="stat-label">Total Packets</div>
                <div class="stat-value">{total_packets:,}</div>
                <div class="stat-subvalue">Captured packets</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">💾</div>
                <div class="stat-label">Total Data</div>
                <div class="stat-value">{total_mb:.2f} MB</div>
                <div class="stat-subvalue">{total_bytes:,} bytes</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">🔀</div>
                <div class="stat-label">Protocols Detected</div>
                <div class="stat-value">{len(main_proto_counter)}</div>
                <div class="stat-subvalue">Unique protocol types</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">🖥️</div>
                <div class="stat-label">Source IPs</div>
                <div class="stat-value">{unique_src_ips}</div>
                <div class="stat-subvalue">Unique source addresses</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">🎯</div>
                <div class="stat-label">Destination IPs</div>
                <div class="stat-value">{unique_dst_ips}</div>
                <div class="stat-subvalue">Unique target addresses</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">⚠️</div>
                <div class="stat-label">Security Alerts</div>
                <div class="stat-value">{len(suspicious_ips)}</div>
                <div class="stat-subvalue">Suspicious IPs detected</div>
            </div>
        </div>
        
        <!-- Content -->
        <div class="content">
            <!-- Security Alerts Section -->
            <div class="section">
                <h2 class="section-title">🚨 Security Analysis</h2>
                <div class="alert-box">
                    {generate_security_alerts_html(suspicious_ips, ip_traffic_counter)}
                </div>
            </div>
            
            <!-- Protocol Analysis Charts -->
            <div class="section">
                <h2 class="section-title">📊 Protocol Distribution Analysis</h2>
                <div class="charts-grid">
                    <div class="chart-container">
                        <h3 class="chart-title">🎯 Protocol Distribution</h3>
                        <div id="protocolPieChart"></div>
                    </div>
                    <div class="chart-container">
                        <h3 class="chart-title">📈 Protocol Breakdown</h3>
                        <div id="protocolBarChart"></div>
                    </div>
                </div>
            </div>
            
            <!-- Traffic Analysis Charts -->
            <div class="section">
                <h2 class="section-title">👥 Traffic Volume Analysis</h2>
                <div class="charts-grid">
                    <div class="chart-container">
                        <h3 class="chart-title">🔝 Top Talkers</h3>
                        <div id="topTalkersChart"></div>
                    </div>
                    <div class="chart-container">
                        <h3 class="chart-title">📏 Packet Size Distribution</h3>
                        <div id="packetSizeChart"></div>
                    </div>
                </div>
            </div>
            
            <!-- Top Talkers Table -->
            <div class="section">
                <h2 class="section-title">💬 Detailed Traffic Breakdown</h2>
                <div class="table-container">
                    {generate_top_talkers_table(ip_traffic_counter)}
                </div>
            </div>
            
            <!-- Protocol Details Table -->
            <div class="section">
                <h2 class="section-title">🔍 Protocol Details</h2>
                <div class="table-container">
                    {generate_protocol_table(main_proto_counter, full_proto_counter, total_packets)}
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <div class="footer-content">
                <div class="footer-text">
                    Generated by NetScope Traffic Analyzer | Powered by Python + Scapy + Plotly
                </div>
                <div class="footer-badge">
                    Advanced Network Analysis v2.0
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Protocol Pie Chart
        {protocol_chart}
        
        // Top Talkers Chart
        {top_talkers_chart}
        
        // Packet Size Chart
        {packet_size_chart}
        
        // Protocol Bar Chart
        {protocol_bar_chart}
    </script>
</body>
</html>
"""
    
    # Save dashboard
    output_file = os.path.join(output_dir, "dashboard.html")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✓ HTML Dashboard created: {output_file}")
    return output_file


def format_duration(seconds):
    """Format duration in human-readable format"""
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
            <span style="font-size: 48px;">✅</span>
            <div>
                <strong>No Security Threats Detected</strong><br>
                <span style="font-size: 14px;">All traffic appears normal</span>
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
                    High traffic volume detected: {bytes_transferred:,} bytes ({mb_transferred:.2f} MB)
                </div>
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
                <th>IP Address</th>
                <th>Bytes Transferred</th>
                <th>Megabytes (MB)</th>
                <th>Percentage</th>
            </tr>
        </thead>
        <tbody>
    '''
    
    total_bytes = sum(ip_traffic_counter.values())
    
    for idx, (ip, bytes_val) in enumerate(top_talkers, 1):
        mb = bytes_val / 1024 / 1024
        percentage = (bytes_val / total_bytes * 100) if total_bytes > 0 else 0
        html += f'''
        <tr>
            <td><strong>#{idx}</strong></td>
            <td><code>{ip}</code></td>
            <td>{bytes_val:,}</td>
            <td>{mb:.2f} MB</td>
            <td>{percentage:.1f}%</td>
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
                <th>Percentage</th>
                <th>Sample Protocol Chain</th>
            </tr>
        </thead>
        <tbody>
    '''
    
    # Create a mapping of main protocols to their full chains
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
            <td><strong>{proto}</strong></td>
            <td>{count:,}</td>
            <td>{percentage:.1f}%</td>
            <td><code>{sample_chain}</code></td>
        </tr>
        '''
    
    html += '</tbody></table>'
    return html


def generate_protocol_pie_chart(proto_counter):
    """Generate Plotly pie chart for protocols"""
    protocols = list(proto_counter.keys())
    counts = list(proto_counter.values())
    
    chart_json = {
        'data': [{
            'labels': protocols,
            'values': counts,
            'type': 'pie',
            'hole': 0.4,
            'marker': {
                'colors': ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a', '#fee140', '#30cfd0']
            },
            'textinfo': 'label+percent',
            'textfont': {'size': 12},
            'hovertemplate': '<b>%{label}</b><br>Packets: %{value}<br>Percentage: %{percent}<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 20, 'b': 20, 'l': 20, 'r': 20},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'showlegend': True,
            'legend': {'orientation': 'v', 'x': 1, 'y': 0.5}
        }
    }
    
    return f"Plotly.newPlot('protocolPieChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"


def generate_protocol_bar_chart(proto_counter):
    """Generate Plotly bar chart for protocols"""
    protocols = list(proto_counter.keys())
    counts = list(proto_counter.values())
    
    chart_json = {
        'data': [{
            'x': protocols,
            'y': counts,
            'type': 'bar',
            'marker': {
                'color': counts,
                'colorscale': 'Viridis',
                'showscale': False
            },
            'text': counts,
            'textposition': 'outside',
            'hovertemplate': '<b>%{x}</b><br>Packets: %{y}<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 20, 'b': 80, 'l': 60, 'r': 20},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'xaxis': {'title': 'Protocol', 'tickangle': -45},
            'yaxis': {'title': 'Packet Count', 'gridcolor': '#e2e8f0'},
        }
    }
    
    return f"Plotly.newPlot('protocolBarChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"


def generate_top_talkers_chart(ip_traffic_counter):
    """Generate Plotly bar chart for top talkers"""
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
                'colorscale': 'Portland',
                'showscale': False
            },
            'text': [f"{mb:.2f} MB" for mb in mbs],
            'textposition': 'outside',
            'hovertemplate': '<b>%{y}</b><br>%{x:.2f} MB<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 20, 'b': 40, 'l': 120, 'r': 80},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'xaxis': {'title': 'Data (MB)', 'gridcolor': '#e2e8f0'},
            'yaxis': {'title': '', 'autorange': 'reversed'},
        }
    }
    
    return f"Plotly.newPlot('topTalkersChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"


def generate_packet_size_chart(df):
    """Generate Plotly histogram for packet sizes"""
    if df.empty or 'length' not in df.columns:
        return "// No packet size data"
    
    sizes = df['length'].tolist()
    
    chart_json = {
        'data': [{
            'x': sizes,
            'type': 'histogram',
            'nbinsx': 50,
            'marker': {
                'color': '#667eea',
                'line': {'color': 'white', 'width': 1}
            },
            'hovertemplate': 'Size: %{x} bytes<br>Count: %{y}<extra></extra>'
        }],
        'layout': {
            'height': 400,
            'margin': {'t': 20, 'b': 60, 'l': 60, 'r': 20},
            'paper_bgcolor': 'rgba(0,0,0,0)',
            'plot_bgcolor': 'rgba(0,0,0,0)',
            'xaxis': {'title': 'Packet Size (bytes)', 'gridcolor': '#e2e8f0'},
            'yaxis': {'title': 'Frequency', 'gridcolor': '#e2e8f0'},
            'bargap': 0.1
        }
    }
    
    return f"Plotly.newPlot('packetSizeChart', {json.dumps(chart_json['data'])}, {json.dumps(chart_json['layout'])});"