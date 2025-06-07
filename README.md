# **ThreatX IDS**

        `▄▄▄▄▄▄▄▄▄▄▄``▄`````````▄``▄▄▄▄▄▄▄▄▄▄▄``▄▄▄▄▄▄▄▄▄▄▄``▄▄▄▄▄▄▄▄▄▄▄``▄▄▄▄▄▄▄▄▄▄▄``▄```````▄`
        ▐░░░░░░░░░░░▌▐░▌```````▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌`````▐░▌
        `▀▀▀▀█░█▀▀▀▀`▐░▌```````▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀`▐░█▀▀▀▀▀▀▀█░▌`▀▀▀▀█░█▀▀▀▀``▐░▌```▐░▌`
        `````▐░▌`````▐░▌```````▐░▌▐░▌```````▐░▌▐░▌``````````▐░▌```````▐░▌`````▐░▌```````▐░▌`▐░▌``
        `````▐░▌`````▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄`▐░█▄▄▄▄▄▄▄█░▌`````▐░▌````````▐░▐░▌```
        `````▐░▌`````▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌`````▐░▌`````````▐░▌````
        `````▐░▌`````▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀█░█▀▀`▐░█▀▀▀▀▀▀▀▀▀`▐░█▀▀▀▀▀▀▀█░▌`````▐░▌````````▐░▌░▌```
        `````▐░▌`````▐░▌```````▐░▌▐░▌`````▐░▌``▐░▌``````````▐░▌```````▐░▌`````▐░▌```````▐░▌`▐░▌``
        `````▐░▌`````▐░▌```````▐░▌▐░▌``````▐░▌`▐░█▄▄▄▄▄▄▄▄▄`▐░▌```````▐░▌`````▐░▌``````▐░▌```▐░▌`
        `````▐░▌`````▐░▌```````▐░▌▐░▌```````▐░▌▐░░░░░░░░░░░▌▐░▌```````▐░▌`````▐░▌`````▐░▌`````▐░▌
        ``````▀```````▀`````````▀``▀`````````▀``▀▀▀▀▀▀▀▀▀▀▀``▀`````````▀```````▀```````▀```````▀`

**ThreatX** is a lightweight yet powerful Intrusion Detection System (IDS) built with Python. It passively monitors network traffic to identify and log various cyber threats in real time. Designed for flexibility and clarity, **ThreatX** detects attacks such as **DoS**, **SQL Injection**, **XSS**, **port scanning**, **malware signatures**, **unauthorized login attempts**, and **ARP spoofing** using customizable rule-based signatures.

Whether you're testing your IDS setup or exploring packet-level threat detection, **ThreatX** offers a reliable and developer-friendly foundation for network security analytics and threat research.


## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/THARAGESHWARAN-SATHYAMOORTHY/ThreatX
   ```

2. **Navigate to the Project Directory**

   ```bash
   cd ThreatX
   ```

3. **Install Required Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Tool**

   ```bash
   python main.py
   ```

> 🔐 On first run, you'll be prompted to set a login password to access ThreatX.

> 💡 Ensure your network interface is active and configured properly for packet sniffing.
