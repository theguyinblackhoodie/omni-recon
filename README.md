# 🦅 OmniRecon - Advanced Hybrid Network Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20Android-green?style=for-the-badge)
![Engine](https://img.shields.io/badge/Engine-Hybrid%20(Scapy%20%2B%20Ping)-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

**OmniRecon** is a robust, cross-platform Network Reconnaissance tool engineered to solve common scanning failures on Windows and Android environments.

Unlike traditional scanners that often crash due to Npcap/WinPcap driver conflicts or strict firewalls, OmniRecon utilizes a proprietary **"Hybrid Scanning Engine"**. It intelligently attempts a fast Scapy/ARP scan first, and if it detects issues, it automatically switches to a native System Ping sweep. This ensures **100% device detection reliability**.

---

## 🚀 Key Features

* **🛡️ Hybrid Scanning Engine:** Automatically switches between ARP Packet Injection and Native Ping Sweeps to bypass firewall/driver restrictions.
* **📱 Fing-Style Recognition:** Identifies **Device Vendors** (Apple, Samsung, etc.) and resolves **Hostnames** on the network.
* **🔌 Smart Interface Detection:** Automatically detects the active internet interface (ignoring virtual adapters like VMWare/VirtualBox).
* **🌍 Integrated OSINT Tools:**
    * **DNS Lookup:** Resolve Domain names to IP addresses.
    * **GeoIP:** Fetch location, ISP, and coordinates of an IP.
    * **Whois:** Retrieve domain registration and expiry details.
* **⚡ Multi-Threaded:** Scans entire subnets (255 IPs) in seconds using concurrent threading.

---

## 🛠️ Installation

### Prerequisites
Ensure you have **Python 3.x** installed.

### 1. Clone the Repository

git clone [https://github.com/theguyinblackhoodie/omni-recon.git](https://github.com/theguyinblackhoodie/omni-recon.git)

cd OmniRecon
2. Install Dependencies
Run the following command to install required libraries:

pip install scapy requests colorama python-whois

⚠️ Windows Users: You must install Npcap for Scapy to work correctly. During installation, ensure you check the box "Install in WinPcap API-compatible Mode".

💻 Usage Instructions
Since this tool interacts with network interfaces, it requires Administrator or Root privileges.

🪟 Windows
Run Command Prompt (CMD) or PowerShell as Administrator:

python OmniRecon.py

🐧 Linux / macOS
Run the script using sudo:

sudo python3 OmniRecon.py

📱 Android (Termux)
You need Root Access on your device for full scanning features.

Install dependencies:

pkg install python scapy tsu
Run with root permissions:

sudo python OmniRecon.py

(Note: Without root, the ARP scan may be limited, but OSINT features will still work.)


<img width="1592" height="813" alt="image" src="https://github.com/user-attachments/assets/4413217e-f891-4f35-898e-93db36705a91" />


⚠️ Troubleshooting
"No devices found" / Only 1 device found?

Ensure you are running the tool as Administrator/Root.

On Windows, check if your WiFi Network Profile is set to "Private". If it is set to "Public", Windows blocks network discovery.

Scapy/Driver Errors:

Reinstall Npcap and ensure "WinPcap API-compatible Mode" is selected.

⚖️ Disclaimer
OmniRecon is developed for educational purposes and valid network testing only. Do not use this tool on networks you do not own or have explicit permission to audit. The author is not responsible for any misuse or damage caused by this program.

👤 Author
TheGuyInBlackHoodie

GitHub: @theguyinblackhoodie
