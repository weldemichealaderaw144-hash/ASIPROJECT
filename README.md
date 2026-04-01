# 🚀 ASIPROJECT

### የጥቃት ሜዳ መረጃ ፕላትፎርም (Attack Surface Intelligence Platform)
https://github.com/weldemichealaderaw144-hash/ASIPROJECT.git
---ከURL በመጠቀም Clone ያድርጉ

## 📌 አጠቃላይ እይታ

ASI Project የሳይበር ደህንነት (Cyber Security) ፕላትፎርም ሲሆን ለ reconnaissance, bug bounty, እና SOC analysis የተሟላ መሳሪያዎችን ያቀርባል።

ይህ ፕላትፎርም የእርስዎን assets መፈለግ፣ የጥቃት ሜዳ ትንተና ማድረግ እና vulnerabilities መለየት በራሱ ያደርጋል።

---

## 🔧 የተካተቱ መሣሪያዎች

subfinder → ፈጣን subdomain መፈለጊያ  
amass → የጥቃት ሜዳ ማስፋፊያ  
assetfinder → domain እና subdomain መፈለጊያ  
dnsx → DNS መሣሪያ  
httpx → HTTP probing እና ቴክኖሎጂ መለያየት  
katana → Web crawler  
gau → ታሪካዊ URLs መሰብሰቢያ  
nuclei → vulnerability scanner  
gowitness → screenshot መሣሪያ (pending)  
whatweb → የድህረገጽ ቴክኖሎጂ መለያየት  
theHarvester → Email እና OSINT መረጃ  
wappalyzer → Tech stack መለያየት  

---

## ⚙️ ቅድመ ሁኔታዎች

እነዚህን አስቀድሞ ይጫኑ:

Go  
Python  
Git  
Node.js (npm)  

---

## 🐧 Kali Linux ላይ መጫን

sudo apt update  
sudo apt install golang-go python3 python3-pip git npm -y  

### መሣሪያዎችን መጫን

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  
go install -v github.com/OWASP/Amass/v3/...@master  
go install github.com/tomnomnom/assetfinder@latest  
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest  
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install github.com/projectdiscovery/katana/cmd/katana@latest  
go install github.com/lc/gau/v2/cmd/gau@latest  
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  
go install github.com/sensepost/gowitness@latest  

### ሌሎች መሣሪያዎች

sudo apt install whatweb theharvester -y  
npm install -g wappalyzer  

### PATH ማስተካከል

echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc  
source ~/.bashrc  

---

## 🪟 Windows ላይ መጫን

Go አጫን እና %GOPATH%\bin ወደ PATH ያክሉ  

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest  
go install -v github.com/OWASP/Amass/v3/...@master  
go install github.com/tomnomnom/assetfinder@latest  
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest  
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install github.com/projectdiscovery/katana/cmd/katana@latest  
go install github.com/lc/gau/v2/cmd/gau@latest  
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  
go install github.com/sensepost/gowitness@latest  

💡 Tip: WSL2 + Kali Linux መጠቀም ይመከራል  

---

## ▶️ አጠቃቀም ምሳሌዎች

subfinder -d example.com -silent  

amass enum -d example.com  

gau example.com  

cat subdomains.txt | httpx -status-code -title  

nuclei -u https://example.com -t cves/  

---

## 🧠 ASI ምንድን ነው?

Attack Surface Intelligence (ASI) ማለት የአንድ organization የሚታዩ እና የሚደርሱ ቴክኖሎጂ ንብረቶችን (assets) መሰብሰብ፣ መከታተል እና አደጋ መገምገም ነው።

---

## 📦 Assets

Main Domain → example.com  
Subdomains → api.example.com, dev.example.com  
URLs → https://example.com/login  
Server IPs → 192.168.1.10  
Ports → 22, 80, 443  
Services → nginx:80, apache:443  
Technologies → WordPress, React, Cloudflare  
Emails → admin@example.com  
Cloud → AWS S3, Azure, GCP  
API → /api/v1/users  

---

## 🎯 ዓላማ

መረጃዎችን በአንድ ቦታ ማሰባሰብ፣ monitoring ማድረግ እና የደህንነት አደጋ መገምገም ነው።

---

## 🔐 አጠቃቀም

Bug Bounty  
Red Team Recon  
SOC Monitoring  
Asset Inventory  

---

## 👨‍💻 ደራሲ

Weldemicheal 🇪🇹  
Cyber Security Enthusiast
