#!/bin/bash

# 13 VPN regions in ALPHABETICAL order
VPNS=(
    "australia-east"
    "central-india"
    "central-us"
    "chile-central"
    "east-us"
    "japan-east"
    "malaysia-west"
    "poland-central"
    "south-africa-north"
    "south-central-us"
    "uae-north"
    "uk-south"
    "west-us"
)

# VM IPs for each region
VM_IPS_australia_east="20.5.51.80"
VM_IPS_uae_north="74.162.153.11"
VM_IPS_south_central_us="13.85.179.73"
VM_IPS_east_us="172.176.243.12"
VM_IPS_uk_south="20.90.176.214"
VM_IPS_malaysia_west="20.17.178.166"
VM_IPS_poland_central="134.112.41.45"
VM_IPS_central_us="20.241.90.236"
VM_IPS_west_us="4.227.98.101"
VM_IPS_chile_central="68.211.112.128"
VM_IPS_south_africa_north="40.127.13.204"
VM_IPS_japan_east="130.33.113.111"
VM_IPS_central_india="40.81.230.182"

SSH_KEY="$HOME/.ssh/azure_rtc"
OUTPUT_DIR="$HOME/captures/whatsapp-manual-169"
RESULTS_CSV="$OUTPUT_DIR/test_results.csv"
PROGRESS_FILE="$OUTPUT_DIR/.progress"

mkdir -p "$OUTPUT_DIR"

# Function to save progress
save_progress() {
    echo "$1" > "$PROGRESS_FILE"
}

# Function to get last completed test
get_last_test() {
    if [ -f "$PROGRESS_FILE" ]; then
        cat "$PROGRESS_FILE"
    else
        echo "0"
    fi
}

# Create CSV header if file doesn't exist
if [ ! -f "$RESULTS_CSV" ]; then
    echo "Test#,Host_VPN,Client_VPN,Host_VM_IP,Client_VM_IP,Packets_Captured,Primary_Relay_IP,Primary_Relay_Hostname,Primary_Location,Primary_Packets,RTT_ms,Timestamp" > "$RESULTS_CSV"
fi

# Get starting test number
LAST_TEST=$(get_last_test)
test_number=$((LAST_TEST + 1))

if [ $LAST_TEST -gt 0 ]; then
    echo "=========================================="
    echo "RESUMING FROM TEST #$test_number"
    echo "=========================================="
    echo ""
    echo "Last completed test: #$LAST_TEST"
    echo ""
    read -p "Press ENTER to continue from test #$test_number..."
else
    echo "=========================================="
    echo "MANUAL 169 WHATSAPP TESTS"
    echo "=========================================="
    echo ""
    echo "SETUP INSTRUCTIONS:"
    echo "1. Both iPhones connected to 'WhatsApp-Test' WiFi"
    echo "2. Both iPhones have all 13 VPN profiles configured"
    echo "3. You'll manually switch VPNs as prompted"
    echo ""
    echo "CONTROLS:"
    echo "  - To PAUSE and resume later: Press Ctrl+C"
    echo "  - To RETRY a failed test: Type 'retry' when asked"
    echo "  - Progress is saved after each test"
    echo ""
    read -p "Press ENTER when ready to start..."
fi

# Calculate which host/client VPN to start from
start_host_index=$(( (test_number - 1) / 13 ))
start_client_index=$(( (test_number - 1) % 13 ))

# Outer loop: Host VPN (13 iterations)
for host_index in $(seq $start_host_index 12); do
    host_vpn="${VPNS[$host_index]}"
    
    # Get host IP using variable indirection
    host_var="VM_IPS_${host_vpn//-/_}"
    host_ip="${!host_var}"
    
    echo ""
    echo ""
    echo "######################################################"
    echo "###                                                ###"
    echo "###   🔵 SWITCH HOST PHONE VPN NOW 🔵             ###"
    echo "###                                                ###"
    echo "######################################################"
    echo ""
    echo "HOST VPN: $host_vpn"
    echo ""
    echo ">>> iPhone 1 (HOST) → Connect to VPN: $host_vpn <<<"
    echo ""
    read -p "⏸️  Press ENTER when HOST VPN is connected to $host_vpn... "
    
    # Inner loop: Client VPN (13 iterations)
    start_client=$start_client_index
    for client_index in $(seq $start_client 12); do
        client_vpn="${VPNS[$client_index]}"
        
        # Reset start_client_index after first host VPN
        start_client_index=0
        
        # Get client IP using variable indirection
        client_var="VM_IPS_${client_vpn//-/_}"
        client_ip="${!client_var}"
        
        # Flag to control retry logic
        retry_test=true
        
        while $retry_test; do
            echo ""
            echo ""
            echo "======================================================"
            echo "===                                                ==="
            echo "===   🟢 SWITCH CLIENT PHONE VPN NOW 🟢           ==="
            echo "===                                                ==="
            echo "======================================================"
            echo ""
            echo "Test $test_number/169"
            echo "Host: $host_vpn → Client: $client_vpn"
            echo ""
            echo ">>> iPhone 2 (CLIENT) → Connect to VPN: $client_vpn <<<"
            echo ""
            read -p "⏸️  Press ENTER when CLIENT VPN is connected to $client_vpn... "
            
            # Start packet capture on client VM
            echo ""
            echo "Starting packet capture on $client_vpn VM..."
            CAPTURE_START=$(ssh -i "$SSH_KEY" azureuser@$client_ip "curl -X POST 'http://localhost:5000/start?iface=wg0'" 2>&1)
            
            if echo "$CAPTURE_START" | grep -q "started"; then
                echo "✓ Capture started successfully"
            else
                echo "❌ ERROR: Failed to start capture on $client_vpn VM"
                echo "$CAPTURE_START"
                echo ""
                read -p "Type 'retry' to try again, or press ENTER to skip: " response
                if [ "$response" = "retry" ]; then
                    continue
                else
                    retry_test=false
                    ((test_number++))
                    continue 2
                fi
            fi
            
            echo ""
            echo ""
            echo "******************************************************"
            echo "***                                                ***"
            echo "***   📞 MAKE WHATSAPP CALL NOW! 📞               ***"
            echo "***                                                ***"
            echo "***   Call duration: 30 seconds                   ***"
            echo "***                                                ***"
            echo "******************************************************"
            echo ""
            read -p "⏹️  Press ENTER when call is COMPLETE... "
            
            # Stop capture
            echo ""
            echo "Stopping capture..."
            PCAP_PATH=$(ssh -i "$SSH_KEY" azureuser@$client_ip "curl -X POST 'http://localhost:5000/stop'" 2>/dev/null | grep -oE '/var/log/rtc/[^"]+')
            
            if [ -z "$PCAP_PATH" ]; then
                echo "❌ ERROR: Failed to stop capture or get PCAP path"
                echo ""
                read -p "Type 'retry' to redo this test, or press ENTER to skip: " response
                if [ "$response" = "retry" ]; then
                    continue
                else
                    retry_test=false
                    ((test_number++))
                    continue 2
                fi
            fi
            
            # Get packet count
            PACKET_COUNT=$(ssh -i "$SSH_KEY" azureuser@$client_ip "sudo iptables -L FORWARD -v -n | grep wg0 | head -1 | awk '{print \$1}'" 2>/dev/null)
            
            # Check if packet count is reasonable (at least 100 packets)
            if [ -z "$PACKET_COUNT" ] || [ "$PACKET_COUNT" -lt 100 ]; then
                echo "⚠️  WARNING: Low or no packet count ($PACKET_COUNT packets)"
                echo ""
                read -p "Type 'retry' to redo this test, or press ENTER to continue anyway: " response
                if [ "$response" = "retry" ]; then
                    continue
                fi
            fi
            
            # Download PCAP
            OUTPUT_FILE="$OUTPUT_DIR/test_${test_number}_${host_vpn}_to_${client_vpn}.pcap"
            scp -i "$SSH_KEY" azureuser@$client_ip:$PCAP_PATH "$OUTPUT_FILE" 2>/dev/null
            
            if [ ! -f "$OUTPUT_FILE" ]; then
                echo "❌ ERROR: Failed to download PCAP file"
                echo ""
                read -p "Type 'retry' to redo this test, or press ENTER to skip: " response
                if [ "$response" = "retry" ]; then
                    continue
                else
                    retry_test=false
                    ((test_number++))
                    continue 2
                fi
            fi
            
            # Analyze ALL relay servers with locations
            echo "Analyzing relay servers..."
            
            # Get all destination IPs sorted by packet count, excluding VMs and private IPs
            RELAY_DATA=$(tshark -r "$OUTPUT_FILE" -T fields -e ip.dst 2>/dev/null | \
                grep -v '^10\.' | grep -v '^172\.' | grep -v '^192\.168\.' | \
                grep -v "^${host_ip}$" | grep -v "^${client_ip}$" | \
                sort | uniq -c | sort -rn | head -10)
            
            # Process relays and display
            PRIMARY_RELAY_IP=""
            PRIMARY_RELAY_HOSTNAME=""
            PRIMARY_LOCATION=""
            PRIMARY_PACKETS=""
            
            while read count ip; do
                if [ ! -z "$ip" ]; then
                    # Get hostname
                    hostname=$(nslookup "$ip" 2>/dev/null | grep 'name =' | awk '{print $NF}' | sed 's/\.$//')
                    if [ -z "$hostname" ]; then
                        hostname="$ip"
                    fi
                    
                    # Extract location from hostname (e.g., iad3, nrt1, fra5)
                    location=$(echo "$hostname" | grep -oE '\-[a-z]{3}[0-9]' | sed 's/^-//' | tr '[:lower:]' '[:upper:]')
                    if [ -z "$location" ]; then
                        location="UNKNOWN"
                    fi
                    
                    # Display with IP address
                    echo "  $count packets → $ip ($hostname) [$location]"
                    
                    # Save first one as primary
                    if [ -z "$PRIMARY_RELAY_IP" ]; then
                        PRIMARY_RELAY_IP="$ip"
                        PRIMARY_RELAY_HOSTNAME="$hostname"
                        PRIMARY_LOCATION="$location"
                        PRIMARY_PACKETS="$count"
                    fi
                fi
            done <<< "$RELAY_DATA"
            
            # Set defaults if no relays found
            if [ -z "$PRIMARY_RELAY_IP" ]; then
                PRIMARY_RELAY_IP="N/A"
                PRIMARY_RELAY_HOSTNAME="NONE"
                PRIMARY_LOCATION="N/A"
                PRIMARY_PACKETS="0"
            fi
            
            # Calculate RTT (placeholder)
            RTT_MS="TBD"
            
            # Save to CSV
            TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
            echo "$test_number,$host_vpn,$client_vpn,$host_ip,$client_ip,$PACKET_COUNT,$PRIMARY_RELAY_IP,$PRIMARY_RELAY_HOSTNAME,$PRIMARY_LOCATION,$PRIMARY_PACKETS,$RTT_MS,$TIMESTAMP" >> "$RESULTS_CSV"
            
            echo ""
            echo "✅ Test $test_number complete!"
            echo "   Packets captured: $PACKET_COUNT"
            echo "   Primary relay: $PRIMARY_RELAY_IP ($PRIMARY_RELAY_HOSTNAME) [$PRIMARY_LOCATION]"
            echo ""
            
            # Save progress after successful test
            save_progress "$test_number"
            
            # Reset iptables counters
            ssh -i "$SSH_KEY" azureuser@$client_ip "sudo iptables -Z" 2>/dev/null
            
            # Exit retry loop
            retry_test=false
            
            ((test_number++))
        done
    done
    
    echo ""
    echo "✅ Completed all 13 tests for HOST VPN: $host_vpn"
    echo "   Progress: $((test_number - 1))/169 tests complete"
    echo ""
done

echo ""
echo "=========================================="
echo "🎉 ALL 169 TESTS COMPLETE! 🎉"
echo "=========================================="
echo ""
echo "Results saved to: $RESULTS_CSV"
echo "PCAPs saved to: $OUTPUT_DIR/"
echo ""

# Remove progress file since we're done
rm -f "$PROGRESS_FILE"

echo "Next steps:"
echo "1. Analyze $RESULTS_CSV for relay patterns"
echo "2. Create RTT heatmap from data"
echo "3. Generate relay server usage statistics"
echo ""

# Generate summary
echo "Generating summary..."
python3 << PYTHON
import csv
import sys
from collections import Counter

csv_file = "$RESULTS_CSV"
relay_counter = Counter()
location_counter = Counter()
total_packets = 0
test_count = 0

try:
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['Primary_Relay_Hostname'] != 'NONE':
                relay_counter[row['Primary_Relay_IP']] += 1
                if row['Primary_Location'] != 'N/A':
                    location_counter[row['Primary_Location']] += 1
            try:
                total_packets += int(row['Packets_Captured'])
                test_count += 1
            except:
                pass
    
    print("\n========================================")
    print("SUMMARY STATISTICS")
    print("========================================")
    print(f"Total tests: {test_count}")
    print(f"Total packets captured: {total_packets:,}")
    print(f"Average packets per test: {total_packets//test_count if test_count > 0 else 0}")
    
    print("\nTop 5 relay IPs:")
    for relay_ip, count in relay_counter.most_common(5):
        print(f"  {relay_ip}: {count} calls")
    
    print("\nTop relay locations:")
    for location, count in location_counter.most_common(10):
        print(f"  {location}: {count} calls")
        
except Exception as e:
    print(f"Error generating summary: {e}", file=sys.stderr)
PYTHON

