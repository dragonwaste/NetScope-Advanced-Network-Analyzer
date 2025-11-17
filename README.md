# NetScope - Network Traffic Analyzer

Advanced network traffic analysis tool for PCAP files.

## 🎯 What Does This Tool Do?

NetScope analyzes network traffic captured in PCAP files and generates:
- 📊 Interactive HTML dashboard
- 📈 Traffic visualizations (charts, graphs)
- 📄 Detailed reports (CSV, TXT)
- 🚨 Security analysis (suspicious activity detection)

---

## 🚀 Quick Start

### Option 1: Analyze Your Own Traffic

**If you already have a PCAP file:**

1. Copy your PCAP file to the project folder and rename it:
```bash
copy your_capture.pcap traffic.pcap
```

2. Run the analyzer:
```bash
python main.py
```

3. Open the results:
```bash
output/dashboards/dashboard.html
```

---

### Option 2: Generate Sample Data (For Testing/Demo)

**If you don't have a PCAP file:**

1. Generate sample traffic:
```bash
python create_sample_pcap.py
```

2. This creates `traffic.pcap` automatically

3. Run the analyzer:
```bash
python main.py
```

4. View results:
```bash
output/dashboards/dashboard.html
```

---

## 📦 Installation

1. **Install Python 3.8+** (if not installed)

2. **Clone/Download this project**

3. **Create virtual environment:**
```bash
python -m venv venv
```

4. **Activate virtual environment:**
```bash
# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

5. **Install dependencies:**
```bash
pip install -r requirements.txt
```

---

## 📁 How to Get a PCAP File?

### Method 1: Capture Your Own Traffic

**Using Wireshark:**
1. Download Wireshark: https://www.wireshark.org/
2. Start capture on your network interface
3. Browse the internet for a few minutes
4. Stop capture
5. Save as → `traffic.pcap`
6. Copy to NetScope folder

**Using tcpdump (Linux/Mac):**
```bash
sudo tcpdump -i eth0 -w traffic.pcap -c 100
```

### Method 2: Use Sample Files

**Download public samples:**
- https://www.netresec.com/?page=PcapFiles
- https://wiki.wireshark.org/SampleCaptures

### Method 3: Generate Demo Data
```bash
python create_sample_pcap.py
```

---

## 🎨 Output Files

After running `python main.py`, you'll find:
```
output/
├── dashboards/
│   └── dashboard.html          ← 🌟 Open this in your browser!
├── visualizations/
│   ├── protocol_distribution.html
│   ├── top_talkers.html
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
- Detection thresholds
- Output directories
- Display options

---

## 🛠️ Technologies

- **Python 3.x**
- **Scapy** - Packet manipulation
- **Plotly** - Interactive charts
- **Pandas** - Data analysis
- **Rich** - Terminal formatting

---

## 📝 Project Structure
```
NetScope/
├── main.py                    # 🎯 Main analyzer (run this!)
├── create_sample_pcap.py      # 🔧 Sample data generator
├── traffic.pcap               # 📦 Input file (your PCAP goes here)
├── config/
├── src/
├── output/                    # 📁 Results appear here
└── ...
```

---

## 👨‍💻 Usage Examples

### Basic Analysis
```bash
python main.py
```

### With Custom PCAP
```bash
# Rename your file:
copy my_network.pcap traffic.pcap

# Run:
python main.py
```

### Generate Multiple Samples
```bash
python create_sample_pcap.py
python main.py

# Results in output/
```

---

## 🎓 For Educational Use

This tool is designed for:
- Learning network protocols
- Understanding traffic analysis
- Cybersecurity education
- Network troubleshooting

**⚠️ Privacy Note:** Never analyze traffic without permission. 
Use only on your own networks or public sample files.

---

## 📞 Support

For questions about this project, refer to the documentation in `docs/` folder.

---

## 📄 License

Educational Project - For Learning Purposes