ASIPROJECT
Attack Surface Intelligence Platform

ASI Project የሳይበር ደህንነት (Cyber Security) መረጃ ማሰባሰቢያ ፕላትፎርም ነው፤ በተለይም reconnaissance እና bug bounty ስራዎች ላይ የሚያግዝ።

It is a curated toolkit designed for security researchers, bug hunters, and SOC analysts to automate asset discovery and vulnerability detection.

🔧 Tools Included (መሳሪያዎች)
Tool	Description
subfinder	ፈጣን subdomain enumeration
amass	Advanced attack surface mapping
assetfinder	Domain & subdomain discovery
dnsx	DNS resolution toolkit
httpx	HTTP probing & service detection
katana	Web crawling & spidering
gau	Historical URL collection
nuclei	Vulnerability scanning (templates-based)
gowitness	Web screenshots (pending)
whatweb	Technology fingerprinting
theHarvester	Emails & OSINT gathering
wappalyzer	Tech stack detection
⚙️ Prerequisites (ቅድመ ሁኔታ)

Ensure you have the following installed:

Go → for most tools
Python → for OSINT tools
Git → to clone repository
Node.js (npm) → for Wappalyzer
🐧 Installation – Kali Linux
sudo apt update
sudo apt install golang-go python3 python3-pip git npm -y
Install Tools (በ Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
Other Tools
sudo apt install whatweb theharvester -y
npm install -g wappalyzer
Fix PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
🪟 Installation – Windows
Install Go and set PATH (%GOPATH%\bin)
Open PowerShell / CMD
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
Optional (Recommended)

👉 Use WSL2 + Kali Linux for better compatibility

▶️ Usage Examples (አጠቃቀም)
# Subdomain discovery
subfinder -d example.com -silent

# Attack surface mapping
amass enum -d example.com

# Find URLs
gau example.com

# Probe live hosts
cat subdomains.txt | httpx -status-code -title

# Scan vulnerabilities
nuclei -u https://example.com -t cves/
🧠 ASI Concept (ምንድነው ASI?)

Attack Surface Intelligence (ASI) ማለት:

👉 የአንድ organization ያሉትን

Domains
Subdomains
IPs
APIs
Services

መሰብሰብ፣ መቆጣጠር እና አደጋ (risk) መገምገም ነው።

🔐 Use Cases
Bug Bounty Hunting
Red Team Reconnaissance
SOC Monitoring
Asset Inventory Management
📌 Future Improvements
Web Dashboard (Flask / React)
Risk Scoring System
Automation Pipelines
Cloud Asset Detection
👨‍💻 Author

Weldemicheal (Ethiopia 🇪🇹)
Cyber Security Enthusiast | ASI Developer
