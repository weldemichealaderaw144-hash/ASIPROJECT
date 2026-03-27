# 🚀 ASIPROJECT

### Attack Surface Intelligence Platform

---

## 📌 Overview

**ASI Project** የሳይበር ደህንነት (Cyber Security) ፕላትፎርም ሲሆን ለ **reconnaissance**, **bug bounty**, እና **SOC analysis** የተሟላ መሳሪያዎችን ያቀርባል።

It helps you **discover assets, analyze attack surface, and detect vulnerabilities** automatically.

---

## 🔧 Tools Included

* **subfinder** → Fast subdomain discovery
* **amass** → Advanced attack surface mapping
* **assetfinder** → Find domains & subdomains
* **dnsx** → DNS resolution toolkit
* **httpx** → HTTP probing & tech detection
* **katana** → Web crawler & spider
* **gau** → Get historical URLs
* **nuclei** → Vulnerability scanner
* **gowitness** → Screenshot tool *(pending)*
* **whatweb** → Website technology detection
* **theHarvester** → Emails & OSINT gathering
* **wappalyzer** → Tech stack detection

---

## ⚙️ Prerequisites

Make sure you have installed:

* Go
* Python
* Git
* Node.js (npm)

---

## 🐧 Kali Linux Installation

```bash
sudo apt update
sudo apt install golang-go python3 python3-pip git npm -y
```

### Install Tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
```

### Other Tools

```bash
sudo apt install whatweb theharvester -y
npm install -g wappalyzer
```

### Fix PATH

```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 🪟 Windows Installation

Install Go and ensure `%GOPATH%\\bin` is in PATH.

```cmd
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
```

💡 Tip: Use **WSL2 + Kali Linux** for better experience

---

## ▶️ Usage Examples

```bash
# Subdomain discovery
subfinder -d example.com -silent

# Attack surface mapping
amass enum -d example.com

# Find URLs
gau example.com

# Probe live hosts
cat subdomains.txt | httpx -status-code -title

# Vulnerability scan
nuclei -u https://example.com -t cves/
```

---

🧠 What is ASI?

Attack Surface Intelligence (ASI) ማለት የአንድ organization የሚታዩ እና የሚደርሱ የቴክኖሎጂ ንብረቶችን (assets) መሰብሰብ፣ መቆጣጠር እና አደጋ (risk) መገምገም ነው።

📦 Assets Included
Main Domain
example.com, server.local
Subdomains (comma-separated)
api.example.com, dev.example.com
Web Endpoints / URLs
https://example.com/login
https://example.com/admin
Server IPs
192.168.1.10, 10.0.0.5
Open Ports
22, 80, 443
Services (format: service:port or name)
nginx:80, apache:443, ssh
Technologies (CMS, Frameworks, CDN)
WordPress, React, Cloudflare
Email Addresses
admin@example.com, support@example.com
Cloud Assets
myapp-bucket, storage.azure.com
(AWS S3, Azure Storage, GCP buckets)
API Endpoints
/api/v1/users, /api/auth/login

👉 Goal:
መረጃዎቹን በአንድ ቦታ ማሰባሰብ፣ መከታተል (monitoring) እና የደህንነት አደጋዎችን መገምገም (risk assessment) ነው።
---

## 🔐 Use Cases

* Bug Bounty Hunting
* Red Team Recon
* SOC Monitoring
* Asset Inventory

----

## 👨‍💻 Author

**Weldemicheal 🇪🇹**
Cyber Security Enthusiast

