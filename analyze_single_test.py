#!/usr/bin/env python3

import subprocess
import sys
from collections import defaultdict

def get_relay_hostname(ip):
    """Get hostname for relay IP."""
    cmd = f"nslookup {ip} 2>/dev/null | grep 'name =' | awk '{{print $NF}}' | sed 's/\\.$//' "
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    hostname = result.stdout.strip() if result.stdout.strip() else ip
    
    import re
    location = "UNKNOWN"
    if hostname != ip:
        match = re.search(r'-([a-z]{3}\d+)', hostname.lower())
        if match:
            location = match.group(1).upper()
    
    return hostname, location

def analyze_pcap(pcap_file, side_name):
    """Analyze PCAP for STUN relays."""
    cmd = f'tshark -r {pcap_file} -Y "udp.port == 3478" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e udp.srcport -e udp.dstport 2>/dev/null'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if not result.stdout:
        return {}
    
    relay_rtts = defaultdict(list)
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
    
    for req_time, req_src, req_dst, req_port in requests:
        for resp_time, resp_src, resp_dst, resp_port in responses:
            if (resp_src == req_dst and resp_dst == req_src and 
                resp_port == req_port and resp_time > req_time and
                (resp_time - req_time) < 2.0):
                rtt = (resp_time - req_time) * 1000
                relay_rtts[req_dst].append(rtt)
                break
    
    return relay_rtts

if len(sys.argv) < 2:
    print("Usage: python3 analyze_single_test.py <test_number>")
    print("Example: python3 analyze_single_test.py 5")
    sys.exit(1)

test_num = sys.argv[1]
base_dir = "/Users/sujal/captures/dual-169-tests"

# Read CSV to find test info
import csv
test_info = None
with open(f"{base_dir}/test_results.csv", 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['Test#'] == test_num:
            test_info = row
            break

if not test_info:
    print(f"Test {test_num} not found in CSV")
    sys.exit(1)

host_vpn = test_info['Host_VPN']
client_vpn = test_info['Client_VPN']
same_vm = test_info['Same_VM'] == 'YES'

print("=" * 80)
print(f"RELAY ANALYSIS - Test {test_num}: {host_vpn} → {client_vpn}")
print("=" * 80)
print()

if same_vm:
    # Single PCAP
    pcap_file = test_info['Host_PCAP']
    print(f"Same VM test - analyzing single PCAP: {pcap_file}")
    print()
    
    relay_rtts = analyze_pcap(pcap_file, "Combined")
    
    if not relay_rtts:
        print("No STUN relays found")
        sys.exit(0)
    
    relay_data = []
    for relay_ip, rtts in relay_rtts.items():
        hostname, location = get_relay_hostname(relay_ip)
        median_rtt = sorted(rtts)[len(rtts)//2]
        relay_data.append({
            'ip': relay_ip,
            'hostname': hostname,
            'location': location,
            'exchanges': len(rtts),
            'median_rtt': median_rtt
        })
    
    relay_data.sort(key=lambda x: x['exchanges'], reverse=True)
    
    print(f"Found {len(relay_data)} relay servers:")
    print()
    for i, relay in enumerate(relay_data, 1):
        print(f"Relay #{i}: {relay['location']}")
        print(f"  IP: {relay['ip']}")
        print(f"  Hostname: {relay['hostname']}")
        print(f"  STUN exchanges: {relay['exchanges']}")
        print(f"  Median RTT: {relay['median_rtt']:.2f} ms")
        print()

else:
    # Two PCAPs
    host_pcap = test_info['Host_PCAP']
    client_pcap = test_info['Client_PCAP']
    
    print(f"Host PCAP: {host_pcap}")
    print(f"Client PCAP: {client_pcap}")
    print()
    
    host_rtts = analyze_pcap(host_pcap, "Host")
    client_rtts = analyze_pcap(client_pcap, "Client")
    
    all_relays = set(host_rtts.keys()) | set(client_rtts.keys())
    
    if not all_relays:
        print("No STUN relays found")
        sys.exit(0)
    
    relay_data = []
    for relay_ip in all_relays:
        hostname, location = get_relay_hostname(relay_ip)
        
        h_rtts = host_rtts.get(relay_ip, [])
        c_rtts = client_rtts.get(relay_ip, [])
        
        h_median = sorted(h_rtts)[len(h_rtts)//2] if h_rtts else None
        c_median = sorted(c_rtts)[len(c_rtts)//2] if c_rtts else None
        
        total_exchanges = len(h_rtts) + len(c_rtts)
        total_rtt = (h_median + c_median) if (h_median and c_median) else None
        
        relay_data.append({
            'ip': relay_ip,
            'hostname': hostname,
            'location': location,
            'host_exchanges': len(h_rtts),
            'client_exchanges': len(c_rtts),
            'total_exchanges': total_exchanges,
            'host_rtt': h_median,
            'client_rtt': c_median,
            'total_rtt': total_rtt
        })
    
    relay_data.sort(key=lambda x: x['total_exchanges'], reverse=True)
    
    print(f"Found {len(relay_data)} relay servers:")
    print()
    
    for i, relay in enumerate(relay_data, 1):
        print(f"Relay #{i}: {relay['location']}")
        print(f"  IP: {relay['ip']}")
        print(f"  Hostname: {relay['hostname']}")
        print(f"  STUN exchanges: {relay['total_exchanges']} (Host: {relay['host_exchanges']}, Client: {relay['client_exchanges']})")
        if relay['host_rtt']:
            print(f"  Host → Relay RTT: {relay['host_rtt']:.2f} ms")
        if relay['client_rtt']:
            print(f"  Client → Relay RTT: {relay['client_rtt']:.2f} ms")
        if relay['total_rtt']:
            print(f"  Total Path RTT: {relay['total_rtt']:.2f} ms")
        print()

