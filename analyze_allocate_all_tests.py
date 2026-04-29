#!/usr/bin/env python3

import subprocess
from collections import defaultdict

# All three test configurations
TESTS = [
    {
        "name": "Test 1: Australia-East → UAE-North",
        "host_pcap": "/Users/sujal/captures/dual-capture/host_australia-east.pcap",
        "client_pcap": "/Users/sujal/captures/dual-capture/client_uae-north.pcap"
    },
    {
        "name": "Test 2: Chile-Central → Central-US",
        "host_pcap": "/Users/sujal/captures/dual-capture/host_chile-central.pcap",
        "client_pcap": "/Users/sujal/captures/dual-capture/client_central-us.pcap"
    },
    {
        "name": "Test 3: Central-India → Central-US",
        "host_pcap": "/Users/sujal/captures/dual-capture/host_central-india.pcap",
        "client_pcap": "/Users/sujal/captures/dual-capture/client_central-us.pcap"
    }
]

def extract_allocate_requests(pcap_file, endpoint_name):
    """Extract TURN Allocate requests specifically."""
    
    # TURN Allocate has message type 0x0003
    cmd = f'tshark -r {pcap_file} -Y "stun.type == 0x0003" -T fields -e frame.time_epoch -e ip.src -e ip.dst 2>/dev/null'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if not result.stdout:
        return defaultdict(int)
    
    lines = result.stdout.strip().split('\n')
    
    # Count Allocate requests per relay
    allocate_counts = defaultdict(int)
    
    for line in lines:
        parts = line.split('\t')
        if len(parts) == 3:
            timestamp, src_ip, dst_ip = parts
            
            # Request from 10.x to external relay
            if src_ip.startswith('10.'):
                allocate_counts[dst_ip] += 1
    
    return allocate_counts

print("=" * 100)
print("TURN ALLOCATE REQUEST ANALYSIS - ALL THREE TESTS")
print("=" * 100)
print()
print("Verifying paper's claim: 'Each device sends two TURN Allocate requests to each candidate'")
print()

overall_verified = True

for test in TESTS:
    print("=" * 100)
    print(test["name"])
    print("=" * 100)
    print()
    
    # Extract Allocate requests from both PCAPs
    host_allocates = extract_allocate_requests(test["host_pcap"], "Host")
    client_allocates = extract_allocate_requests(test["client_pcap"], "Client")
    
    # Combine relay lists
    all_relays = set(host_allocates.keys()) | set(client_allocates.keys())
    
    if not all_relays:
        print("❌ No TURN Allocate requests found")
        print()
        overall_verified = False
        continue
    
    print(f"Found {len(all_relays)} relay servers receiving Allocate requests")
    print()
    
    # Display table
    print(f"{'Relay IP':<20} {'Host Allocates':<20} {'Client Allocates':<20} {'Total':<10}")
    print("-" * 100)
    
    for relay_ip in sorted(all_relays):
        host_count = host_allocates.get(relay_ip, 0)
        client_count = client_allocates.get(relay_ip, 0)
        total = host_count + client_count
        
        print(f"{relay_ip:<20} {host_count:<20} {client_count:<20} {total:<10}")
    
    print()
    
    # Check if claim is verified for this test
    test_verified = True
    for relay_ip in all_relays:
        host_count = host_allocates.get(relay_ip, 0)
        client_count = client_allocates.get(relay_ip, 0)
        
        if host_count != 2 or client_count != 2:
            test_verified = False
            break
    
    if test_verified:
        print("✅ Paper's claim VERIFIED for this test")
    else:
        print("❌ Paper's claim NOT VERIFIED for this test:")
        for relay_ip in all_relays:
            host_count = host_allocates.get(relay_ip, 0)
            client_count = client_allocates.get(relay_ip, 0)
            
            expected = "✓" if (host_count == 2 and client_count == 2) else "✗"
            print(f"  {expected} {relay_ip}: Host={host_count} (expected 2), Client={client_count} (expected 2)")
        overall_verified = False
    
    print()

# Final summary
print("=" * 100)
print("OVERALL SUMMARY")
print("=" * 100)
print()

if overall_verified:
    print("✅ Paper's claim is VERIFIED across all tests")
    print("   Each endpoint sends exactly 2 TURN Allocate requests to each candidate relay")
else:
    print("❌ Paper's claim is NOT VERIFIED")
    print("   The Allocate request pattern differs from '2 requests per endpoint per candidate'")
    print()
    print("Possible explanations:")
    print("  1. WhatsApp's protocol has changed since the paper was published")
    print("  2. The tshark STUN filter isn't capturing all Allocate messages correctly")
    print("  3. WhatsApp uses a different STUN message type for relay negotiation")
    print("  4. The behavior varies based on network conditions or WhatsApp version")

