# ASIPROJECT
ASI Project
# ASIPROJECT – Reconnaissance Toolkit

A curated collection of powerful reconnaissance and bug‑bounty tools, packaged together for easy installation and use on **Kali Linux** and **Windows**.  

Includes:

- [subfinder](https://github.com/projectdiscovery/subfinder) – fast subdomain enumeration  
- [amass](https://github.com/OWASP/Amass) – in‑depth attack surface mapping  
- [assetfinder](https://github.com/tomnomnom/assetfinder) – find domains and subdomains  
- [dnsx](https://github.com/projectdiscovery/dnsx) – fast and multi‑purpose DNS toolkit  
- [httpx](https://github.com/projectdiscovery/httpx) – HTTP probing and information gathering  
- [katana](https://github.com/projectdiscovery/katana) – next‑generation crawling and spidering  
- [gau](https://github.com/lc/gau) – get all URLs (AlienVault’s Open Threat Exchange)  
- [nuclei](https://github.com/projectdiscovery/nuclei) – fast vulnerability scanner  
- [gowitness](https://github.com/sensepost/gowitness) – web screenshot utility *(pending)*  
- [whatweb](https://github.com/urbanadventurer/WhatWeb) – web technology fingerprinting  
- [theHarvester](https://github.com/laramies/theHarvester) – email, domain, and subdomain enumeration  
- [wappalyzer](https://github.com/AliasIO/wappalyzer) – technology stack detection  

---

## Prerequisites

- **Go** (for tools written in Go)  
- **Python** (for theHarvester and WhatWeb)  
- **Git** (to clone the repository)  

### Install Go

#### Kali Linux
```bash
sudo apt update
sudo apt install golang-go
sudo apt install python3 python3-pip
most tools are installed using go.....
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
go install -v github.com/OWASP/Amass/v3/...@master

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Gau
go install github.com/lc/gau/v2/cmd/gau@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Gowitness (pending – install anyway)
go install github.com/sensepost/gowitness@latest

# WhatWeb
sudo apt install whatweb

# theHarvester
sudo apt install theharvester

# Wappalyzer (requires Node.js)
sudo apt install npm
npm install -g wappalyzer
After installation, ensure that $HOME/go/bin is in your PATH:echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc


------------------------------------------
in Windows
Install Go (see prerequisites) and make sure %GOPATH%\bin is in your PATH.

Open a Command Prompt (or PowerShell) and run the following:
:: Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

:: Amass
go install -v github.com/OWASP/Amass/v3/...@master

:: Assetfinder
go install github.com/tomnomnom/assetfinder@latest

:: Dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

:: Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

:: Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

:: Gau
go install github.com/lc/gau/v2/cmd/gau@latest

:: Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

:: Gowitness (pending)
go install github.com/sensepost/gowitness@latest


For WhatWeb and theHarvester, you can use WSL (Windows Subsystem for Linux) or install them via Git and Python manually:

WhatWeb:

cmd
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
gem install bundler
bundle install
Then run with ruby whatweb.rb.

theHarvester:

cmd
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements.txt
Run with python theHarvester.py.


Wappalyzer:

cmd
npm install -g wappalyzer
Tip: For a smoother experience on Windows, consider using WSL2 with a Kali distribution – then you can follow the Kali instructions

-----------------------------------


Subfinder
bash
subfinder -d example.com -silent
Amass
bash
amass enum -d example.com
Assetfinder
bash
assetfinder --subs-only example.com
Dnsx
bash
# Resolve subdomains from a file
cat subdomains.txt | dnsx -a -resp
Httpx
bash
# Probe live hosts from subdomains
cat subdomains.txt | httpx -status-code -title -tech-detect
Katana
bash
# Crawl a domain
katana -u https://example.com
Gau
bash
# Get URLs from historical data
gau example.com
Nuclei
bash
# Run templates on a target
nuclei -u https://example.com -t cves/
Gowitness (pending)
bash
# Take screenshots from a list of URLs
gowitness file -f urls.txt
WhatWeb
bash
whatweb https://example.com
theHarvester
bash
theHarvester -d example.com -b all
Wappalyzer
bash
wappalyzer https://example.com
