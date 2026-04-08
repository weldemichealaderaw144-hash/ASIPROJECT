# 🚀 ASIPROJECT

### የጥቃት ሜዳ መረጃ ፕላትፎርም (Attack Surface Intelligence Platform)

🔗 GitHub:
https://github.com/weldemichealaderaw144-hash/ASIPROJECT.git

📥 Clone ለማድረግ:

```bash
 git clone https://github.com/weldemichealaderaw144-hash/ASIPROJECT.git
  cd ASIPROJECT
```

---

# 📌 አጠቃላይ እይታ

**ASI Project** የሳይበር ደህንነት ፕላትፎርም ሲሆን ለ:

* Reconnaissance
* Bug Bounty
* SOC Analysis

የተሟላ መሣሪያዎችን ያቀርባል።

👉 የorganization assets መፈለግ
👉 attack surface ትንተና
👉 vulnerabilities መለየት
👉 የስጋት ደረጃ መገምገም

---

# 🔧 የተካተቱ መሣሪያዎች (All Tools)

### 🌐 Subdomain & Asset Discovery

SUBFINDER_PATH = find_tool("subfinder")
👉 subdomains ለመፈለግ

AMASS_PATH = find_tool("amass")
👉 ትልቅ attack surface mapping

ASSETFINDER_PATH = find_tool("assetfinder")
👉 ቀላል subdomain discovery

---

### 🌍 Web Probing & Crawling

HTTPX_PATH = find_tool("httpx")
👉 live websites ለመፈተሽ

KATANA_PATH = find_tool("katana")
👉 URLs & endpoints crawling

GAU_PATH = find_tool("gau")
👉 archived URLs ለማግኘት

---

### 🔍 Vulnerability Scanning

NUCLEI_PATH = find_tool("nuclei")
👉 vulnerabilities ፈጣን scan

SUBZY_PATH = find_tool("subzy")
👉 subdomain takeover ለመፈለግ

---

### 🌐 Network & DNS Analysis

NAABU_PATH = find_tool("naabu")
👉 open ports scan

DNSX_PATH = find_tool("dnsx")
👉 DNS verification

---

### 🖥️ Technology Detection

WHATWEB_PATH = find_tool("whatweb")
👉 server & CMS detection

WAPPALYZER_PATH = find_tool("wappalyzer")
👉 frameworks & libraries detection

---

### 📸 Visualization & OSINT

GOWITNESS_PATH = find_tool("gowitness")
👉 website screenshot

THEHARVESTER_PATH = find_tool("theharvester")
👉 email & OSINT data collection

---

# ⚙️ ቅድመ ሁኔታዎች (Prerequisites)

* Go
* Python
* Git
* Node.js (npm)

---

# 🐧 Kali Linux ላይ መጫን

```bash
sudo apt update
sudo apt install golang-go python3 python3-pip git npm -y
```

---

# 🧰 Tools መጫኛ (Install All)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
go install github.com/PentestPad/subzy@latest
```

---

# 🟢 PATH ማስተካከል

```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

# ▶️ አጠቃቀም ምሳሌ

```bash
subfinder -d example.com -silent
amass enum -d example.com
gau example.com
cat subdomains.txt | httpx -status-code -title
naabu -host example.com
nuclei -u https://example.com
```

---

# 🧠 ASI ምንድን ነው?

ASI = የorganization የሚታዩ assets መሰብሰብ እና አደጋ መገምገም

---

# 📦 Assets

* Domain
* Subdomain
* URLs
* IP
* Ports
* Services
* Technologies
* Emails
* Cloud
* APIs

---

# 🎯 ዓላማ

✔️ መረጃ ማሰባሰብ
✔️ Monitoring
✔️ Risk Analysis

---

# 🔐 አጠቃቀም

* Bug Bounty
* Red Team
* SOC
* Asset Management

---

# 👨‍💻 ደራሲ

**Weldemicheal 🇪🇹**
Cyber Security Enthusiast
