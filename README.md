# ZeroOsintX
# 🔍 ZeroOsintX v1.0

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)

**Professional OSINT & Reconnaissance Framework**

*Developed by ZeroTraceX (Ahsan Mughal) | Powered by Roothackerslab*

</div>

---

## 📌 About

ZeroOsintX is a powerful OSINT toolkit for security researchers and penetration testers. Gather intelligence across domains, IPs, emails, phone numbers, and social media with beautiful interactive reports.

## ✨ Features

- 🌐 **Domain Scan** - WHOIS, DNS records, subdomain enumeration
- 🌍 **IP Lookup** - Geolocation, ISP info, reverse DNS
- 👤 **Social Media** - Username search across 7+ platforms
- 📧 **Email Intel** - Breach check, domain validation, social links
- 📱 **Phone OSINT** - Operator detection, network info (Pakistan focus)
- 🔍 **Website Analysis** - Headers, SSL certs, metadata
- 📊 **Beautiful Reports** - Auto-generated HTML & JSON reports

---

## 🚀 Installation

### Quick Setup

```bash
# Clone repository
git clone https://github.com/roothackerslab/ZeroOsintX.git
cd ZeroOsintX

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate          # Linux/macOS
venv\Scripts\activate             # Windows CMD
venv\Scripts\Activate.ps1         # Windows PowerShell

# Install dependencies
pip install -r requirements.txt

# Run tool
python zero.py
```

### Windows PowerShell Users

If you get execution policy error, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 📖 Usage

```bash
# Activate environment (if not already active)
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate       # Windows

# Run ZeroOsintX
python zero.py
```

### Main Menu

```
1 • 🌐 Domain Scan       - Complete domain reconnaissance
2 • 🌍 IP Scan           - IP geolocation & reverse DNS
3 • 👤 Social Media Scan - Username search across platforms
4 • 🔍 Website Scan      - Website analysis & metadata
5 • 📧 Email Scan        - Email intelligence & breach check
6 • 📱 Phone Scan        - Phone OSINT (operator, network)
7 • 📊 View Reports      - Open saved reports
0 • ❌ Exit
```

### Examples

```bash
# Domain scan
Enter domain: example.com

# IP scan
Enter IP: 8.8.8.8

# Social media scan
Enter username: johndoe

# Email scan
Enter email: user@example.com

# Phone scan (Pakistan)
Enter phone: 03001234567
```

---

## 📊 Reports

All scans generate:
- **HTML Reports** - Beautiful interactive dashboards
- **JSON Reports** - Structured data for automation

Reports are saved in `zero_reports/` directory:

```
zero_reports/
├── index.html              # Master dashboard
├── domain/
├── ip/
├── email/
└── phone/
```

View reports: `Option 7` from menu or open `zero_reports/index.html`

---

## ⚙️ Configuration (Optional)

```bash
# Copy config example
cp config_example.py config.py

# Edit settings
nano config.py
```

**Available Options:**
- Custom subdomain wordlists
- API keys (Hunter.io, Shodan, VirusTotal)
- Timeout and threading settings
- Proxy configuration
- Rate limiting

---

## 🛡️ Ethical Use

⚠️ **Important:** This tool is for **authorized security research only**.

✅ **Legal Use:**
- Your own systems
- Authorized penetration testing
- Bug bounty programs
- Educational purposes

❌ **Illegal Use:**
- Unauthorized access
- Harassment/stalking
- Privacy violations
- Malicious activity

**Always get permission before scanning any target.**

---

## 🔧 Troubleshooting

### Module not found
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Permission denied (Linux/macOS)
```bash
chmod +x zero.py
python zero.py
```

### DNS resolution failed
Check internet connection and try different DNS servers in config

### Timeout errors
Increase timeout in `config.py`: `TIMEOUT = 15`

---

## 🤝 Contributing

Contributions welcome! 

1. Fork the repo
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file

---

## 📞 Contact

**ZeroTraceX (Ahsan Mughal)**
- GitHub: [@roothackerslab](https://github.com/roothackerslab)
- Email: roothackerslab.git@example.com


---

## 🙏 Credits

Built with:
- [Python](https://www.python.org/)
- [Rich](https://github.com/Textualize/rich) - Terminal UI
- [Requests](https://requests.readthedocs.io/) - HTTP library
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- [dnspython](https://www.dnspython.org/) - DNS toolkit

---

<div align="center">

### ⭐ Star us on GitHub!

**Use responsibly. Happy researching!**

Made with ❤️ by [ZeroTraceX](https://github.com/roothackerslab)

</div>
