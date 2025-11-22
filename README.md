<div align="center">

# 🌐 NetScope

### Advanced Network Traffic Analyzer

**Transform raw packets into actionable insights**

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Powered%20by-Scapy-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Output](#-output-files) • [Documentation](#-project-structure)

</div>

---

## 📖 About

NetScope is a powerful network traffic analyzer that transforms PCAP files into comprehensive visual reports. Built with Python and Scapy, it features a stunning **futuristic cyberpunk-style dashboard** with interactive charts and detailed security analysis.

### 🎯 What It Does

- **📊 Analyzes** network packets from PCAP files
- **🔍 Detects** suspicious activities and anomalies  
- **📈 Visualizes** traffic patterns with interactive charts
- **📄 Generates** professional HTML dashboards and reports
- **🚨 Identifies** potential security threats

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔬 **Deep Packet Analysis** | Parse and analyze all protocol layers |
| 🌍 **Protocol Detection** | Identify TCP, UDP, ICMP, HTTP, DNS, and more |
| 📊 **Traffic Statistics** | Packet counts, byte volumes, protocol distribution |
| 👥 **Top Talkers** | Identify most active IP addresses |
| 🚨 **Security Alerts** | Flag suspicious high-traffic IPs |
| 🎨 **Cyberpunk Dashboard** | Stunning futuristic HTML reports |
| 📈 **Interactive Charts** | Powered by Plotly |
| 💾 **Multiple Exports** | CSV, TXT, HTML, PNG |

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step-by-Step Setup

**1. Clone the repository**
```bash
git clone https://github.com/dragonwaste/NetScope-Advanced-Network-Analyzer.git
cd NetScope-Advanced-Network-Analyzer
```

**2. Create virtual environment**
```bash
python -m venv venv
```

**3. Activate virtual environment**
```bash
# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

**4. Install dependencies**
```bash
pip install -r requirements.txt
```

---

## 🎯 Usage

### Option 1: Analyze Your Own Traffic

If you have a PCAP file:
```bash
# Copy your PCAP file to the project folder
copy your_capture.pcap traffic.pcap

# Run the analyzer
python main.py

# Open the dashboard
# → output/dashboards/dashboard.html
```

### Option 2: Generate Sample Data (For Testing)

If you don't have a PCAP file:
```bash
# Generate sample traffic
python create_sample_pcap.py

# Run the analyzer
python main.py

# Open the dashboard
# → output/dashboards/dashboard.html
```

---

## 📦 How to Get a PCAP File

### Using Wireshark (Recommended)
1. Download Wireshark: https://www.wireshark.org/
2. Start capture on your network interface
3. Browse the internet for a few minutes
4. Stop capture
5. Save as → `traffic.pcap`
6. Copy to NetScope folder

### Using tcpdump (Linux/Mac)
```bash
sudo tcpdump -i eth0 -w traffic.pcap -c 100
```

### Download Public Samples
- https://www.netresec.com/?page=PcapFiles
- https://wiki.wireshark.org/SampleCaptures

### Generate Demo Data
```bash
python create_sample_pcap.py
```

---

## 📁 Output Files

After running `python main.py`, you'll find:
```
output/
├── dashboards/
│   └── dashboard.html          ← 🌟 Open this in your browser!
├── visualizations/
│   ├── protocol_distribution.html
│   ├── protocol_distribution.png
│   ├── top_talkers.html
│   ├── top_talkers.png
│   └── ...
├── reports/
│   └── summary_report.txt
└── exports/
    ├── report.csv
    └── file_formatted.txt
```

---

## ⚙️ Configuration

Edit `config/settings.json` to customize:
```json
{
    "input": {
        "pcap_file": "traffic.pcap"
    },
    "thresholds": {
        "suspicious_bytes": 1048576,
        "use_adaptive_threshold": false,
        "adaptive_factor": 5
    }
}
```

---

## 📂 Project Structure
```
NetScope/
├── main.py                    # 🎯 Main analyzer (run this!)
├── create_sample_pcap.py      # 🔧 Sample data generator
├── traffic.pcap               # 📦 Input file (your PCAP goes here)
├── requirements.txt           # 📋 Dependencies
├── config/
│   └── settings.json          # ⚙️ Configuration
├── src/
│   ├── analyzer.py            # Core packet analysis
│   ├── visualizer.py          # Chart generation
│   ├── html_dashboard.py      # Dashboard creation
│   └── report_generator.py    # Report formatting
├── output/                    # 📁 Results appear here
└── README.md
```

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| **Python 3.8+** | Core programming language |
| **Scapy** | Packet manipulation and analysis |
| **Pandas** | Data processing |
| **Plotly** | Interactive visualizations |
| **Rich** | Terminal formatting |
| **Matplotlib** | Static chart generation |

---

## 📊 Usage Examples

### Basic Analysis
```bash
python main.py
```

### With Custom PCAP
```bash
copy my_network.pcap traffic.pcap
python main.py
```

### Generate and Analyze Sample
```bash
python create_sample_pcap.py
python main.py
```

---

## 🎓 Educational Use

This tool is designed for:
- 📖 Learning network protocols
- 🔒 Cybersecurity education
- 🎯 Network troubleshooting
- 💼 Professional training
- 🧪 Security research

---

## ⚠️ Disclaimer

**For Educational and Authorized Use Only**

- Only analyze traffic you have permission to capture
- Respect privacy and legal regulations
- Use responsibly and ethically
- Not intended for malicious purposes

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
1. Fork the project
2. Create your feature branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add NewFeature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Mohammad Alaghawani AKA Madness**
- GitHub: [@dragonwaste](https://github.com/dragonwaste)

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

Made with ❤️ and Python

</div>
