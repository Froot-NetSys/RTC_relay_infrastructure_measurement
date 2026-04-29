#!/usr/bin/env python3

import subprocess
from collections import defaultdict

HOST_VPN = "central-india"
CLIENT_VPN = "central-us"
HOST_PCAP = f"/Users/sujal/captures/dual-capture/host_{HOST_VPN}.pcap"
CLIENT_PCAP = f"/Users/sujal/captures/dual-capture/client_{CLIENT_VPN}.pcap"

def extract_relay_rtts(pcap_file, endpoint_name):
    """Extract RTT to each relay from STUN request/response pairs."""
    
    # Get STUN packets with timestamps
    cmd = f'tshark -r {pcap_file} -Y "udp.port == 3478" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport 2>/dev/null'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if not result.stdout:
        return {}
    
    lines = result.stdout.strip().split('\n')
    
    # Parse packets
    requests = []  # (timestamp, src_ip, dst_ip, src_port)
    responses = []  # (timestamp, src_ip, dst_ip, dst_port)
    
    for line in lines:
        parts = line.split('\t')
        if len(parts) == 5:
            timestamp, src_ip, dst_ip, src_port, dst_port = parts
            timestamp = float(timestamp)
            
            # Request: from 10.x to external relay
            if src_ip.startswith('10.') and dst_port == '3478':
                requests.append((timestamp, src_ip, dst_ip, src_port))
            # Response: from external relay to 10.x
            elif dst_ip.startswith('10.') and src_port == '3478':
                responses.append((timestamp, src_ip, dst_ip, dst_port))
    
    # Match requests with responses PER RELAY
    relay_rtts = defaultdict(list)
    relay_info = {}
    
    for req_time, req_src, req_dst, req_port in requests:
        # Find matching response
        for resp_time, resp_src, resp_dst, resp_port in responses:
            if (resp_src == req_dst and 
                resp_dst == req_src and 
                resp_port == req_port and
                resp_time > req_time and
                (resp_time - req_time) < 2.0):
                
                rtt = (resp_time - req_time) * 1000  # ms
                relay_rtts[req_dst].append(rtt)
                
                # Store relay info
                if req_dst not in relay_info:
                    relay_info[req_dst] = {'count': 0}
                relay_info[req_dst]['count'] += 1
                
                break
    
    return relay_rtts, relay_info

def get_relay_hostname(ip):
    """Get hostname for relay IP."""
    cmd = f"nslookup {ip} 2>/dev/null | grep 'name =' | awk '{{print $NF}}' | sed 's/\\.$//' "
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    hostname = result.stdout.strip() if result.stdout.strip() else ip
    
    # Extract location code
    import re
    location = "UNKNOWN"
    if hostname != ip:
        match = re.search(r'-([a-z]{3}\d+)', hostname.lower())
        if match:
            location = match.group(1).upper()
    
    return hostname, location

print("=" * 100)
print("DUAL-SIDED RELAY RTT ANALYSIS")
print(f"Host: {HOST_VPN} → Client: {CLIENT_VPN}")
print("=" * 100)
print()

# Extract RTTs from both PCAPs
print("Analyzing HOST PCAP...")
host_relay_rtts, host_relay_info = extract_relay_rtts(HOST_PCAP, "Host")

print("Analyzing CLIENT PCAP...")
client_relay_rtts, client_relay_info = extract_relay_rtts(CLIENT_PCAP, "Client")

# Find all relays (union of both sides)
all_relay_ips = set(host_relay_rtts.keys()) | set(client_relay_rtts.keys())

if not all_relay_ips:
    print("❌ No STUN relay servers found in either PCAP")
    exit(1)

print(f"\nFound {len(all_relay_ips)} relay servers with STUN responses")
print()

# Gather data for all relays
relay_data = []

for relay_ip in all_relay_ips:
    host_rtts = host_relay_rtts.get(relay_ip, [])
    client_rtts = client_relay_rtts.get(relay_ip, [])
    
    # Get hostname and location
    hostname, location = get_relay_hostname(relay_ip)
    
    # Calculate statistics
    host_median = sorted(host_rtts)[len(host_rtts)//2] if host_rtts else None
    host_avg = sum(host_rtts) / len(host_rtts) if host_rtts else None
    host_count = len(host_rtts)
    
    client_median = sorted(client_rtts)[len(client_rtts)//2] if client_rtts else None
    client_avg = sum(client_rtts) / len(client_rtts) if client_rtts else None
    client_count = len(client_rtts)
    
    total_exchanges = host_count + client_count
    
    relay_data.append({
        'ip': relay_ip,
        'hostname': hostname,
        'location': location,
        'host_median': host_median,
        'host_avg': host_avg,
        'host_count': host_count,
        'client_median': client_median,
        'client_avg': client_avg,
        'client_count': client_count,
        'total_exchanges': total_exchanges,
        'total_path': (host_median + client_median) if (host_median and client_median) else None
    })

# Sort by total STUN exchanges (most active relays first)
relay_data.sort(key=lambda x: x['total_exchanges'], reverse=True)

# Display top 4 relays
top_relays = relay_data[:min(4, len(relay_data))]

print("=" * 100)
print(f"TOP {len(top_relays)} RELAY SERVERS (by STUN activity)")
print("=" * 100)
print()

for i, relay in enumerate(top_relays, 1):
    print(f"Relay #{i}: {relay['location']}")
    print(f"  IP: {relay['ip']}")
    print(f"  Hostname: {relay['hostname']}")
    print(f"  Total STUN exchanges: {relay['total_exchanges']} (Host: {relay['host_count']}, Client: {relay['client_count']})")
    print()
    
    if relay['host_median']:
        print(f"  Host → Relay RTT:")
        print(f"    Median: {relay['host_median']:.2f} ms")
        print(f"    Average: {relay['host_avg']:.2f} ms")
    else:
        print(f"  Host → Relay RTT: No data")
    
    if relay['client_median']:
        print(f"  Client → Relay RTT:")
        print(f"    Median: {relay['client_median']:.2f} ms")
        print(f"    Average: {relay['client_avg']:.2f} ms")
    else:
        print(f"  Client → Relay RTT: No data")
    
    if relay['total_path']:
        print(f"  Total Path RTT: {relay['total_path']:.2f} ms")
    else:
        print(f"  Total Path RTT: Unable to calculate")
    
    print()

# Summary table
print("=" * 100)
print("SUMMARY TABLE")
print("=" * 100)
print(f"{'Rank':<6} {'Location':<15} {'Host→Relay (ms)':<18} {'Client→Relay (ms)':<18} {'Total Path (ms)':<18}")
print("-" * 100)

for i, relay in enumerate(top_relays, 1):
    host_str = f"{relay['host_median']:.2f}" if relay['host_median'] else "No data"
    client_str = f"{relay['client_median']:.2f}" if relay['client_median'] else "No data"
    total_str = f"{relay['total_path']:.2f}" if relay['total_path'] else "N/A"
    
    print(f"{i:<6} {relay['location']:<15} {host_str:<18} {client_str:<18} {total_str:<18}")

print()
print("=" * 100)

# Show which relay was most used
if top_relays:
    primary = top_relays[0]
    print(f"PRIMARY RELAY: {primary['location']} ({primary['ip']})")
    print(f"  Total STUN exchanges: {primary['total_exchanges']}")
    if primary['total_path']:
        print(f"  End-to-end path RTT: {primary['total_path']:.2f} ms")
    print()
    print("WhatsApp selected this relay based on lowest RTT during initial negotiation.")

