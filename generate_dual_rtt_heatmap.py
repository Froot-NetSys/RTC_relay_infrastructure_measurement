#!/usr/bin/env python3

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import subprocess
import os
from collections import defaultdict

# Paths
CSV_FILE = os.path.expanduser("~/captures/dual-169-tests/test_results.csv")
OUTPUT_FILE = os.path.expanduser("~/captures/dual-169-tests/rtt_heatmap.png")

# VPN order (alphabetical)
VPN_ORDER = [
    "australia-east",
    "central-india", 
    "central-us",
    "chile-central",
    "east-us",
    "japan-east",
    "malaysia-west",
    "poland-central",
    "south-africa-north",
    "south-central-us",
    "uae-north",
    "uk-south",
    "west-us"
]

def calculate_rtt_from_dual_pcaps(host_pcap, client_pcap, same_vm):
    """Calculate total path RTT from dual PCAPs."""
    try:
        if same_vm:
            # Single PCAP - just calculate RTT from that
            cmd = f'tshark -r {host_pcap} -Y "udp.port == 3478" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if not result.stdout:
                return None
            
            requests = []
            responses = []
            
            for line in result.stdout.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) == 5:
                    timestamp, src_ip, dst_ip, src_port, dst_port = parts
                    timestamp = float(timestamp)
                    
                    if src_ip.startswith('10.') and dst_port == '3478':
                        requests.append((timestamp, src_ip, dst_ip, src_port))
                    elif dst_ip.startswith('10.') and src_port == '3478':
                        responses.append((timestamp, src_ip, dst_ip, dst_port))
            
            rtts = []
            for req_time, req_src, req_dst, req_port in requests:
                for resp_time, resp_src, resp_dst, resp_port in responses:
                    if (resp_src == req_dst and resp_dst == req_src and 
                        resp_port == req_port and resp_time > req_time and
                        (resp_time - req_time) < 2.0):
                        rtt = (resp_time - req_time) * 1000
                        rtts.append(rtt)
                        break
            
            if rtts:
                return round(np.median(rtts), 2)
            return None
            
        else:
            # Two PCAPs - calculate host RTT and client RTT separately, then sum
            def get_rtts(pcap_file):
                cmd = f'tshark -r {pcap_file} -Y "udp.port == 3478" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport 2>/dev/null'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                
                if not result.stdout:
                    return []
                
                requests = []
                responses = []
                
                for line in result.stdout.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) == 5:
                        timestamp, src_ip, dst_ip, src_port, dst_port = parts
                        timestamp = float(timestamp)
                        
                        if src_ip.startswith('10.') and dst_port == '3478':
                            requests.append((timestamp, src_ip, dst_ip, src_port))
                        elif dst_ip.startswith('10.') and src_port == '3478':
                            responses.append((timestamp, src_ip, dst_ip, dst_port))
                
                # Get RTTs per relay
                relay_rtts = defaultdict(list)
                for req_time, req_src, req_dst, req_port in requests:
                    for resp_time, resp_src, resp_dst, resp_port in responses:
                        if (resp_src == req_dst and resp_dst == req_src and 
                            resp_port == req_port and resp_time > req_time and
                            (resp_time - req_time) < 2.0):
                            rtt = (resp_time - req_time) * 1000
                            relay_rtts[req_dst].append(rtt)
                            break
                
                # Return median RTT to primary relay (most exchanges)
                if relay_rtts:
                    primary_relay = max(relay_rtts.keys(), key=lambda k: len(relay_rtts[k]))
                    return relay_rtts[primary_relay]
                return []
            
            host_rtts = get_rtts(host_pcap)
            client_rtts = get_rtts(client_pcap)
            
            if host_rtts and client_rtts:
                host_median = np.median(host_rtts)
                client_median = np.median(client_rtts)
                total_rtt = host_median + client_median
                return round(total_rtt, 2)
            
            return None
            
    except Exception as e:
        print(f"    Error calculating RTT: {e}")
        return None

print("Loading test results...")
df = pd.read_csv(CSV_FILE)

print(f"Found {len(df)} tests\n")

# Calculate RTT for each test
print("Calculating RTT from dual PCAPs...")
rtts = []

for idx, row in df.iterrows():
    test_num = row['Test#']
    host_vpn = row['Host_VPN']
    client_vpn = row['Client_VPN']
    host_pcap = row['Host_PCAP']
    client_pcap = row['Client_PCAP']
    same_vm = row['Same_VM'] == 'YES'
    
    print(f"  Test {test_num}: {host_vpn:20s} → {client_vpn:20s}...", end=" ", flush=True)
    
    rtt = calculate_rtt_from_dual_pcaps(host_pcap, client_pcap, same_vm)
    
    if rtt is not None:
        rtts.append(rtt)
        print(f"{rtt:7.2f} ms")
    else:
        rtts.append(np.nan)
        print("No RTT data")

# Update dataframe
df['RTT_ms'] = rtts

# Create RTT matrix
print("\nCreating RTT matrix...")
rtt_matrix = np.full((len(VPN_ORDER), len(VPN_ORDER)), np.nan)

for idx, row in df.iterrows():
    host_vpn = row['Host_VPN']
    client_vpn = row['Client_VPN']
    rtt = row['RTT_ms']
    
    if pd.notna(rtt) and host_vpn in VPN_ORDER and client_vpn in VPN_ORDER:
        host_idx = VPN_ORDER.index(host_vpn)
        client_idx = VPN_ORDER.index(client_vpn)
        rtt_matrix[host_idx, client_idx] = rtt

# Determine actual min/max for colormap
valid_rtts = rtt_matrix[~np.isnan(rtt_matrix)]
vmin = 0
vmax = np.ceil(valid_rtts.max() / 100) * 100  # Round up to nearest 100

print(f"\nRTT range: {valid_rtts.min():.2f} - {valid_rtts.max():.2f} ms")
print(f"Using colormap range: {vmin} - {vmax} ms")

# Create heatmap
print("\nGenerating heatmap...")
fig, ax = plt.subplots(figsize=(14, 12))

sns.heatmap(rtt_matrix, 
            xticklabels=VPN_ORDER,
            yticklabels=VPN_ORDER,
            cmap='YlOrRd',
            cbar_kws={'label': 'RTT (ms)'},
            annot=True,
            fmt='.0f',
            linewidths=0.5,
            square=True,
            vmin=vmin,
            vmax=vmax,
            ax=ax)

plt.title('WhatsApp Call RTT Between VPN Regions (Dual-Capture)', fontsize=16, fontweight='bold', pad=20)
plt.xlabel('Client VPN Region', fontsize=12, fontweight='bold')
plt.ylabel('Host VPN Region', fontsize=12, fontweight='bold')

plt.xticks(rotation=45, ha='right')
plt.yticks(rotation=0)

plt.tight_layout()
plt.savefig(OUTPUT_FILE, dpi=300, bbox_inches='tight')
print(f"\n✅ Heatmap saved to: {OUTPUT_FILE}")

# Save updated CSV with RTT values
updated_csv = CSV_FILE.replace('.csv', '_with_rtt.csv')
df.to_csv(updated_csv, index=False)
print(f"✅ Updated CSV saved to: {updated_csv}")

# Print statistics
print(f"\n========================================")
print(f"RTT STATISTICS")
print(f"========================================")
print(f"Tests with RTT data: {len(valid_rtts)}/{len(VPN_ORDER)**2}")
print(f"Min RTT: {valid_rtts.min():.2f} ms")
print(f"Max RTT: {valid_rtts.max():.2f} ms")
print(f"Mean RTT: {valid_rtts.mean():.2f} ms")
print(f"Median RTT: {np.median(valid_rtts):.2f} ms")

print(f"\n📊 To view the heatmap:")
print(f"   open {OUTPUT_FILE}")

