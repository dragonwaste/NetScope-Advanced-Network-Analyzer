# visualizer.py

import matplotlib.pyplot as plt
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px
import networkx as nx
import os
from collections import Counter

def create_protocol_pie_chart(protocol_counter, output_dir="reports/visualizations"):
    """Create a pie chart showing protocol distribution"""
    os.makedirs(output_dir, exist_ok=True)
    
    if not protocol_counter:
        print("⚠ No protocol data to visualize")
        return
    
    # Get data
    protocols = list(protocol_counter.keys())
    counts = list(protocol_counter.values())
    
    # Create figure
    fig = go.Figure(data=[go.Pie(
        labels=protocols,
        values=counts,
        hole=0.3,  # Donut chart
        marker=dict(colors=px.colors.qualitative.Set3),
        textinfo='label+percent',
        textfont_size=12
    )])
    
    fig.update_layout(
        title={
            'text': '🎯 Protocol Distribution',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#2c3e50'}
        },
        showlegend=True,
        height=500,
        paper_bgcolor='#f8f9fa',
        plot_bgcolor='#f8f9fa'
    )
    
    # Save
    output_file = os.path.join(output_dir, "protocol_distribution.html")
    fig.write_html(output_file)
    print(f"✓ Protocol pie chart saved to {output_file}")
    
    # Also save as PNG
    try:
        png_file = os.path.join(output_dir, "protocol_distribution.png")
        fig.write_image(png_file, width=800, height=600)
        print(f"✓ Protocol pie chart (PNG) saved to {png_file}")
    except Exception as e:
        print(f"⚠ Could not save PNG (install kaleido if needed): {e}")


def create_top_talkers_chart(ip_traffic_counter, top_n=15, output_dir="reports/visualizations"):
    """Create bar chart of top talkers"""
    os.makedirs(output_dir, exist_ok=True)
    
    if not ip_traffic_counter:
        print("⚠ No IP traffic data to visualize")
        return
    
    # Get top N
    top_talkers = ip_traffic_counter.most_common(top_n)
    ips = [ip for ip, _ in top_talkers]
    bytes_data = [bytes_val / 1024 / 1024 for _, bytes_val in top_talkers]  # Convert to MB
    
    # Create bar chart
    fig = go.Figure(data=[
        go.Bar(
            y=ips,
            x=bytes_data,
            orientation='h',
            marker=dict(
                color=bytes_data,
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="MB")
            ),
            text=[f"{val:.2f} MB" for val in bytes_data],
            textposition='outside',
            hovertemplate='<b>%{y}</b><br>%{x:.2f} MB<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title={
            'text': f'👥 Top {top_n} Talkers by Traffic Volume',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#2c3e50'}
        },
        xaxis_title="Data Transferred (MB)",
        yaxis_title="IP Address",
        height=500 + (top_n * 20),
        paper_bgcolor='#f8f9fa',
        plot_bgcolor='white',
        showlegend=False
    )
    
    fig.update_yaxes(autorange="reversed")  # Largest at top
    
    # Save
    output_file = os.path.join(output_dir, "top_talkers.html")
    fig.write_html(output_file)
    print(f"✓ Top talkers chart saved to {output_file}")
    
    # Also save as PNG
    try:
        png_file = os.path.join(output_dir, "top_talkers.png")
        fig.write_image(png_file, width=1000, height=500 + (top_n * 20))
        print(f"✓ Top talkers chart (PNG) saved to {png_file}")
    except Exception as e:
        print(f"⚠ Could not save PNG: {e}")


def create_packet_size_distribution(df, output_dir="reports/visualizations"):
    """Create histogram of packet sizes"""
    os.makedirs(output_dir, exist_ok=True)
    
    if df.empty or 'length' not in df.columns:
        print("⚠ No packet size data to visualize")
        return
    
    fig = go.Figure(data=[
        go.Histogram(
            x=df['length'],
            nbinsx=50,
            marker=dict(
                color='#3498db',
                line=dict(color='white', width=1)
            ),
            hovertemplate='Packet Size: %{x} bytes<br>Count: %{y}<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title={
            'text': '📏 Packet Size Distribution',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#2c3e50'}
        },
        xaxis_title="Packet Size (bytes)",
        yaxis_title="Frequency",
        height=500,
        paper_bgcolor='#f8f9fa',
        plot_bgcolor='white',
        showlegend=False
    )
    
    # Save
    output_file = os.path.join(output_dir, "packet_size_distribution.html")
    fig.write_html(output_file)
    print(f"✓ Packet size distribution saved to {output_file}")


def create_protocol_comparison(main_proto_counter, full_proto_counter, output_dir="reports/visualizations"):
    """Create side-by-side comparison of main vs full protocols"""
    os.makedirs(output_dir, exist_ok=True)
    
    if not main_proto_counter or not full_proto_counter:
        print("⚠ No protocol data to visualize")
        return
    
    # Create subplots
    fig = make_subplots(
        rows=1, cols=2,
        subplot_titles=('Main Protocol Layer', 'Full Protocol Chain'),
        specs=[[{'type': 'bar'}, {'type': 'bar'}]]
    )
    
    # Main protocol
    main_protocols = list(main_proto_counter.keys())
    main_counts = list(main_proto_counter.values())
    
    fig.add_trace(
        go.Bar(
            x=main_protocols,
            y=main_counts,
            name='Main Protocol',
            marker_color='#3498db',
            text=main_counts,
            textposition='outside'
        ),
        row=1, col=1
    )
    
    # Full protocol (top 10)
    full_protocols_top = full_proto_counter.most_common(10)
    full_protocols = [p for p, _ in full_protocols_top]
    full_counts = [c for _, c in full_protocols_top]
    
    fig.add_trace(
        go.Bar(
            x=full_protocols,
            y=full_counts,
            name='Full Chain',
            marker_color='#e74c3c',
            text=full_counts,
            textposition='outside'
        ),
        row=1, col=2
    )
    
    fig.update_layout(
        title={
            'text': '📊 Protocol Layer Analysis',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#2c3e50'}
        },
        height=500,
        showlegend=False,
        paper_bgcolor='#f8f9fa',
        plot_bgcolor='white'
    )
    
    fig.update_xaxes(title_text="Protocol", row=1, col=1, tickangle=-45)
    fig.update_xaxes(title_text="Protocol Chain", row=1, col=2, tickangle=-45)
    fig.update_yaxes(title_text="Packet Count", row=1, col=1)
    fig.update_yaxes(title_text="Packet Count", row=1, col=2)
    
    # Save
    output_file = os.path.join(output_dir, "protocol_comparison.html")
    fig.write_html(output_file)
    print(f"✓ Protocol comparison chart saved to {output_file}")


def create_traffic_heatmap(df, output_dir="reports/visualizations"):
    """Create heatmap showing traffic between source and destination IPs"""
    os.makedirs(output_dir, exist_ok=True)
    
    if df.empty or 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
        print("⚠ No IP data to create heatmap")
        return
    
    # Filter out empty IPs
    df_filtered = df[(df['src_ip'] != '') & (df['dst_ip'] != '')]
    
    if df_filtered.empty:
        print("⚠ No valid IP pairs for heatmap")
        return
    
    # Create pivot table
    traffic_matrix = df_filtered.groupby(['src_ip', 'dst_ip']).size().reset_index(name='count')
    
    # Get top IPs
    top_src = traffic_matrix.groupby('src_ip')['count'].sum().nlargest(10).index.tolist()
    top_dst = traffic_matrix.groupby('dst_ip')['count'].sum().nlargest(10).index.tolist()
    
    # Filter matrix
    traffic_matrix = traffic_matrix[
        traffic_matrix['src_ip'].isin(top_src) & 
        traffic_matrix['dst_ip'].isin(top_dst)
    ]
    
    # Pivot
    pivot = traffic_matrix.pivot(index='src_ip', columns='dst_ip', values='count').fillna(0)
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=pivot.columns,
        y=pivot.index,
        colorscale='Blues',
        text=pivot.values,
        texttemplate='%{text}',
        textfont={"size": 10},
        hovertemplate='Source: %{y}<br>Destination: %{x}<br>Packets: %{z}<extra></extra>'
    ))
    
    fig.update_layout(
        title={
            'text': '🔥 Traffic Heatmap (Top 10 IPs)',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 20, 'color': '#2c3e50'}
        },
        xaxis_title="Destination IP",
        yaxis_title="Source IP",
        height=600,
        paper_bgcolor='#f8f9fa'
    )
    
    # Save
    output_file = os.path.join(output_dir, "traffic_heatmap.html")
    fig.write_html(output_file)
    print(f"✓ Traffic heatmap saved to {output_file}")


def generate_all_visualizations(df, main_proto_counter, full_proto_counter, 
                               ip_traffic_counter, output_dir="reports/visualizations"):
    """Generate all visualizations at once"""
    print("\n" + "="*70)
    print("🎨 GENERATING VISUALIZATIONS")
    print("="*70)
    
    create_protocol_pie_chart(main_proto_counter, output_dir)
    create_top_talkers_chart(ip_traffic_counter, top_n=15, output_dir=output_dir)
    create_packet_size_distribution(df, output_dir)
    create_protocol_comparison(main_proto_counter, full_proto_counter, output_dir)
    create_traffic_heatmap(df, output_dir)
    
    print("="*70)
    print(f"✅ All visualizations saved to '{output_dir}/' directory")
    print("="*70 + "\n")