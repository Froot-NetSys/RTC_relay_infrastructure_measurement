# RTC Relay Infrastructure Measurement

Study of relay server selection behavior in WhatsApp, analyzing how geographic VPN location affects TURN relay server choice and RTT characteristics. This project forces WhatsApp traffic through WireGuard VPN tunnels using a hardware firewall, captures packets on both endpoints of a call across 169 VPN pair combinations, and analyzes the resulting relay selection patterns.

---

## Repository Structure

```
RTC_relay_infrastructure_measurement/
├── rtcproxy/                    # Core VPN proxy and packet capture tooling
├── WhatsAppHost/                # Xcode UI automation project (caller device)
├── WhatsAppClient/              # Xcode UI automation project (receiver device)
├── dual_capture_169_tests.sh    # Main manual testing script (all 169 VPN pair tests)
├── run_all_169_tests.sh         # Orchestration script for Xcode automation
└── generate_dual_rtt_heatmap.py # RTT heatmap generator
```

---

## Prerequisites

- 13 Azure Ubuntu VMs, one per region (see region list below)
- Raspberry Pi 4 configured as a WiFi hotspot with iptables firewall
- 2 iPhones with WireGuard installed, connected to the hotspot
- Mac with Xcode installed (for automation scripts)
- SSH key pair for Azure VM access

---

## Part 1: Azure VM Setup

### 1.1 Create VMs in Azure Portal

1. Create all 13 VMs in one resource group (e.g. `RTC`)
2. Name each VM using the pattern `RTC-<Application>-<Location>-<Name>` for easy identification
3. Select one VM per region from the list below
4. Size: **Standard B1s** (1 vCPU, 1 GB RAM) — pick the cheapest available; if unavailable, try a different availability zone
5. Image: **Ubuntu Server 22.04 LTS**
6. Authentication: SSH key — use the same key for all VMs

Generate your SSH key if you don't have one:

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/azure_rtc
```

### 1.2 Networking — Open Required Ports

For each VM, go to **Networking → Add inbound port rules** and add:

| Purpose          | Port  | Protocol | Action |
|------------------|-------|----------|--------|
| RTC Capture API  | 5000  | TCP      | Allow  |
| WireGuard VPN    | 51820 | UDP      | Allow  |
| SSH Access       | 22    | TCP      | Allow  |

### 1.3 Install Dependencies

SSH into each VM:

```bash
ssh -i ~/.ssh/azure_rtc azureuser@<VM_PUBLIC_IP>
```

Then run:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip tshark git wireguard qrencode whois \
                    iptables-persistent netfilter-persistent tcpdump curl

sudo apt install python3.12-venv
mkdir -p "$HOME/.venvs"
python3 -m venv "$HOME/.venvs/rtcproxy"
source "$HOME/.venvs/rtcproxy/bin/activate"
```

### 1.4 Install the RTC Capture Service

The easiest way is to run the install script directly:

```bash
curl -sSL https://raw.githubusercontent.com/chandanacharithap/rtcproxy/main/install.sh | bash
```

Or manually clone and install:

```bash
sudo git clone https://github.com/chandanacharithap/rtcproxy.git /opt/rtcproxy
cd /opt/rtcproxy
pip3 install -r requirements.txt
```

Create the systemd service:

```bash
sudo mkdir -p /var/log/rtc
sudo chown azureuser:azureuser /var/log/rtc
sudo chmod 777 /var/log/rtc

sudo tee /etc/systemd/system/rtcproxy.service <<EOF
[Unit]
Description=RTC Capture API
After=network.target

[Service]
User=azureuser
ExecStart=/home/azureuser/.venvs/rtcproxy/bin/python /opt/rtcproxy/api.py
WorkingDirectory=/opt/rtcproxy
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reexec
sudo systemctl enable rtcproxy
sudo systemctl start rtcproxy
sudo systemctl status rtcproxy
```

The service should show **active (running)** and listening on `0.0.0.0:5000`. Verify with:

```bash
curl -X POST 'http://localhost:5000/start?iface=wg0'
curl -X POST 'http://localhost:5000/stop'
```

---

## Part 2: WireGuard Setup (VM ↔ iPhone)

Run the following on each VM as root (`sudo -i`):

### 2.1 Enable IP Forwarding

```bash
tee /etc/sysctl.d/99-wg-routing.conf >/dev/null <<'SYS'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
SYS

sysctl --system
```

### 2.2 Generate Keys and Build Server Config

```bash
WG_DIR=/etc/wireguard
umask 077
mkdir -p "$WG_DIR"; chmod 700 "$WG_DIR"; cd "$WG_DIR"

[ -f server_private.key ] || (wg genkey | tee server_private.key | wg pubkey > server_public.key)
[ -f phone1_private.key ] || (wg genkey | tee phone1_private.key | wg pubkey > phone1_public.key)
[ -f phone2_private.key ] || (wg genkey | tee phone2_private.key | wg pubkey > phone2_public.key)

SERVER_PRIV="$(cat server_private.key)"
SERVER_PUB="$(cat server_public.key)"
P1_PRIV="$(cat phone1_private.key)"; P1_PUB="$(cat phone1_public.key)"
P2_PRIV="$(cat phone2_private.key)"; P2_PUB="$(cat phone2_public.key)"

EGRESS_IF="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
ENDPOINT="$(curl -s ifconfig.me):51820"

cat > "$WG_DIR/wg0.conf" <<EOF
[Interface]
PrivateKey = ${SERVER_PRIV}
Address    = 10.8.0.1/24
ListenPort = 51820
MTU        = 1380
PostUp   = iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ${EGRESS_IF} -j MASQUERADE
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp   = iptables -A FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o ${EGRESS_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT

[Peer]
PublicKey  = ${P1_PUB}
AllowedIPs = 10.8.0.2/32
PersistentKeepalive = 25

[Peer]
PublicKey  = ${P2_PUB}
AllowedIPs = 10.8.0.3/32
PersistentKeepalive = 25
EOF
```

### 2.3 Generate Phone Configs and QR Codes

```bash
cat > "$WG_DIR/phone1.conf" <<EOF
[Interface]
PrivateKey = ${P1_PRIV}
Address    = 10.8.0.2/24
DNS        = 1.1.1.1

[Peer]
PublicKey  = ${SERVER_PUB}
Endpoint   = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

cat > "$WG_DIR/phone2.conf" <<EOF
[Interface]
PrivateKey = ${P2_PRIV}
Address    = 10.8.0.3/24
DNS        = 1.1.1.1

[Peer]
PublicKey  = ${SERVER_PUB}
Endpoint   = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo '=== Phone 1 (scan) ==='
qrencode -t ansiutf8 < "$WG_DIR/phone1.conf"
echo '=== Phone 2 (scan) ==='
qrencode -t ansiutf8 < "$WG_DIR/phone2.conf"
```

### 2.4 Connect iPhones

On each iPhone: open WireGuard → **Add Tunnel → Scan QR Code**.

> **Important:** Scan Phone 1's QR code on iPhone 1 and Phone 2's QR code on iPhone 2. This distinction matters for tests where both caller and callee use the same VM — each phone must have a unique peer identity on the server.

After connecting, verify the VPN is working by visiting [whatismyipaddress.com](https://whatismyipaddress.com) — it should show the Azure VM's IP and region.

### 2.5 VPN Profile Naming

Name each VPN profile in the WireGuard app exactly as follows (required for the automation scripts):

```
rtc-east-us
rtc-central-us
rtc-west-us
rtc-south-central-us
rtc-chile-central
rtc-uk-south
rtc-poland-central
rtc-uae-north
rtc-japan-east
rtc-central-india
rtc-south-africa-north
rtc-australia-east
rtc-malaysia-west
```

---

## Part 3: Raspberry Pi Hotspot Setup

The Raspberry Pi forces all iPhone traffic through VPN by blocking any non-VPN destination at the network level.

### 3.1 Hotspot Configuration

Install dependencies:

```bash
sudo apt install -y hostapd dnsmasq
```

Configure `/etc/hostapd/hostapd.conf`:

```
interface=wlan0
ssid=WhatsApp-Test
hw_mode=g
channel=6
wpa=2
wpa_passphrase=password
wpa_key_mgmt=WPA-PSK
```

Configure `/etc/dnsmasq.conf`:

```
interface=wlan0
dhcp-range=192.168.50.10,192.168.50.100,12h
```

### 3.2 Firewall Rules

Allow forwarded traffic only to the 13 Azure VM IPs:

```bash
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP

for ip in 20.5.51.80 40.81.230.182 20.241.90.236 68.211.112.128 172.176.243.12 \
          130.33.113.111 20.17.178.166 134.112.41.45 40.127.13.204 13.85.179.73 \
          74.162.153.11 20.90.176.214 4.227.98.101; do
    sudo iptables -A FORWARD -d $ip -j ACCEPT
    sudo iptables -A FORWARD -s $ip -j ACCEPT
done

sudo netfilter-persistent save
```

### 3.3 After Each Reboot

The hotspot configuration does not fully persist across reboots. Run these commands after each restart:

```bash
sudo nmcli device disconnect wlan0
sudo ip addr add 192.168.50.1/24 dev wlan0
sudo systemctl restart hostapd dnsmasq
sudo sysctl -w net.ipv4.ip_forward=1
```

---

## Part 4: Running the Tests

Connect both iPhones to the `WhatsApp-Test` WiFi network before starting.

### Option A: Manual Dual-Capture Tests

`dual_capture_169_tests.sh` runs all 169 VPN pair combinations (13 × 13), prompting you to manually switch VPN profiles on the iPhones between each test. It supports pause, resume, and retry of failed tests.

```bash
bash dual_capture_169_tests.sh
```

**Per-test procedure:**
1. The script prompts you to connect iPhone 1 (host) to VPN A and iPhone 2 (client) to VPN B
2. Confirm in the terminal once both VPNs are connected
3. The script starts packet capture on both Azure VMs simultaneously via the capture API
4. Make a WhatsApp call from iPhone 1 to iPhone 2 and hold for 30 seconds
5. End the call and confirm in the terminal
6. The script stops both captures, downloads the PCAP files, and logs metadata to `test_results.csv`
7. Repeat for the next VPN pair

Results are saved to `~/captures/dual-169-tests/`.

---

### Option B: Xcode UI Automation

`WhatsAppHost` and `WhatsAppClient` are Xcode UI test projects that automate the calling workflow on each iPhone. `run_all_169_tests.sh` launches both in parallel.

#### Setup

1. Open `WhatsAppHost/WhatsAppHost.xcodeproj` in Xcode and set the target device to iPhone 1 (UDID: `00008030-001929543A0A802E`)
2. Open `WhatsAppClient/WhatsAppClient.xcodeproj` in Xcode and set the target device to iPhone 2 (UDID: `00008030-000604C814F2802E`)
3. On both iPhones, trust the developer certificate under **Settings → General → VPN & Device Management**

#### Running

```bash
bash run_all_169_tests.sh
```

This launches both Xcode UI test targets in parallel. The tests use clock synchronization — both sync to the next 60-second boundary before starting — so the caller and receiver stay coordinated. The host test loops through all 13 VPN regions and for each, the client loops through all 13 client VPN regions, covering all 169 combinations automatically.

---

## Part 5: Analyzing Results

### Generate RTT Heatmap

```bash
python3 generate_dual_rtt_heatmap.py
```

Outputs `rtt_heatmap.png` — a 13×13 matrix showing the measured RTT (ms) for every VPN pair combination.

---

## Azure VM Regions and IPs

| Region             | IP             |
|--------------------|----------------|
| australia-east     | 20.5.51.80     |
| central-india      | 40.81.230.182  |
| central-us         | 20.241.90.236  |
| chile-central      | 68.211.112.128 |
| east-us            | 172.176.243.12 |
| japan-east         | 130.33.113.111 |
| malaysia-west      | 20.17.178.166  |
| poland-central     | 134.112.41.45  |
| south-africa-north | 40.127.13.204  |
| south-central-us   | 13.85.179.73   |
| uae-north          | 74.162.153.11  |
| uk-south           | 20.90.176.214  |
| west-us            | 4.227.98.101   |
