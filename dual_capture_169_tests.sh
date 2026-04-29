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
OUTPUT_DIR="$HOME/captures/dual-169-tests"
RESULTS_CSV="$OUTPUT_DIR/test_results.csv"
PROGRESS_FILE="$OUTPUT_DIR/.progress"

mkdir -p "$OUTPUT_DIR"

save_progress() {
    echo "$1" > "$PROGRESS_FILE"
}

get_last_test() {
    if [ -f "$PROGRESS_FILE" ]; then
        cat "$PROGRESS_FILE"
    else
        echo "0"
    fi
}

if [ ! -f "$RESULTS_CSV" ]; then
    echo "Test#,Host_VPN,Client_VPN,Host_VM_IP,Client_VM_IP,Host_PCAP,Client_PCAP,Same_VM,Timestamp" > "$RESULTS_CSV"
fi

LAST_TEST=$(get_last_test)
test_number=$((LAST_TEST + 1))

if [ $LAST_TEST -gt 0 ]; then
    echo "Resuming from test #$test_number..."
    read -p "Press ENTER to continue..."
else
    echo "=========================================="
    echo "DUAL-CAPTURE 169 WHATSAPP TESTS"
    echo "=========================================="
    read -p "Press ENTER when ready to start..."
fi

start_host_index=$(( (test_number - 1) / 13 ))
start_client_index=$(( (test_number - 1) % 13 ))

for host_index in $(seq $start_host_index 12); do
    host_vpn="${VPNS[$host_index]}"
    host_var="VM_IPS_${host_vpn//-/_}"
    host_ip="${!host_var}"
    
    echo ""
    echo "######################################################"
    echo "###   🔵 SWITCH HOST PHONE VPN NOW 🔵             ###"
    echo "######################################################"
    echo "HOST VPN: $host_vpn"
    read -p "⏸️  Press ENTER when HOST VPN is connected to $host_vpn... "
    
    start_client=$start_client_index
    for client_index in $(seq $start_client 12); do
        client_vpn="${VPNS[$client_index]}"
        start_client_index=0
        
        client_var="VM_IPS_${client_vpn//-/_}"
        client_ip="${!client_var}"
        
        retry_test=true
        
        while $retry_test; do
            echo ""
            echo "======================================================"
            echo "===   🟢 SWITCH CLIENT PHONE VPN NOW 🟢           ==="
            echo "======================================================"
            echo "Test $test_number/169: $host_vpn → $client_vpn"
            read -p "⏸️  Press ENTER when CLIENT VPN is connected to $client_vpn... "
            
            # Check if same VM
            SAME_VM=false
            if [ "$host_ip" = "$client_ip" ]; then
                SAME_VM=true
                echo ""
                echo "ℹ️  NOTE: Host and Client use same VM ($host_vpn)"
                echo "   Will capture once (single PCAP for both sides)"
                echo ""
            fi
            
            # Start capture on HOST VM (or shared VM if same)
            echo "Starting packet capture on $host_vpn VM..."
            CAPTURE_START=$(ssh -i "$SSH_KEY" azureuser@$host_ip "curl -X POST 'http://localhost:5000/start?iface=wg0'" 2>&1)
            
            if ! echo "$CAPTURE_START" | grep -q "started"; then
                echo "❌ ERROR: Failed to start capture"
                read -p "Type 'retry' to try again, or ENTER to skip: " response
                [ "$response" = "retry" ] && continue || { retry_test=false; ((test_number++)); continue 2; }
            fi
            echo "✓ Capture started"
            
            # Start CLIENT capture (only if different VM)
            if [ "$SAME_VM" = false ]; then
                sleep 2
                echo "Starting packet capture on $client_vpn VM..."
                CLIENT_CAPTURE=$(ssh -i "$SSH_KEY" azureuser@$client_ip "curl -X POST 'http://localhost:5000/start?iface=wg0'" 2>&1)
                
                if ! echo "$CLIENT_CAPTURE" | grep -q "started"; then
                    echo "❌ ERROR: Failed to start CLIENT capture"
                    ssh -i "$SSH_KEY" azureuser@$host_ip "curl -X POST 'http://localhost:5000/stop'" 2>/dev/null
                    read -p "Type 'retry' to try again, or ENTER to skip: " response
                    [ "$response" = "retry" ] && continue || { retry_test=false; ((test_number++)); continue 2; }
                fi
                echo "✓ Client capture started"
            fi
            
            echo ""
            echo "******************************************************"
            echo "***   📞 MAKE WHATSAPP CALL NOW! 📞               ***"
            echo "***   Call duration: 30 seconds                   ***"
            echo "******************************************************"
            read -p "⏹️  Press ENTER when call is COMPLETE... "
            
            # Stop capture(s)
            if [ "$SAME_VM" = true ]; then
                echo "Stopping capture..."
                PCAP_PATH=$(ssh -i "$SSH_KEY" azureuser@$host_ip "curl -X POST 'http://localhost:5000/stop'" 2>/dev/null | grep -oE '/var/log/rtc/[^"]+')
                
                if [ -z "$PCAP_PATH" ]; then
                    echo "❌ ERROR: Failed to stop capture"
                    read -p "Type 'retry' or ENTER to skip: " response
                    [ "$response" = "retry" ] && continue || { retry_test=false; ((test_number++)); continue 2; }
                fi
                
                # Download single PCAP
                OUTPUT_FILE="$OUTPUT_DIR/test_${test_number}_${host_vpn}_to_${client_vpn}.pcap"
                echo "Downloading PCAP..."
                scp -i "$SSH_KEY" azureuser@$host_ip:$PCAP_PATH "$OUTPUT_FILE" 2>/dev/null
                
                if [ ! -f "$OUTPUT_FILE" ]; then
                    echo "❌ ERROR: Failed to download PCAP"
                    read -p "Type 'retry' or ENTER to skip: " response
                    [ "$response" = "retry" ] && continue || { retry_test=false; ((test_number++)); continue 2; }
                fi
                
                # Save to CSV (same file for both host and client columns)
                TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
                echo "$test_number,$host_vpn,$client_vpn,$host_ip,$client_ip,$OUTPUT_FILE,$OUTPUT_FILE,YES,$TIMESTAMP" >> "$RESULTS_CSV"
                
                echo ""
                echo "✅ Test $test_number complete!"
                echo "   PCAP: $(basename $OUTPUT_FILE)"
                
            else
                # Different VMs - stop and download both
                echo "Stopping HOST capture..."
                HOST_PCAP_PATH=$(ssh -i "$SSH_KEY" azureuser@$host_ip "curl -X POST 'http://localhost:5000/stop'" 2>/dev/null | grep -oE '/var/log/rtc/[^"]+')
                
                if [ -z "$HOST_PCAP_PATH" ]; then
                    echo "❌ ERROR: Failed to stop HOST capture"
                    read -p "Type 'retry' or ENTER to skip: " response
                    [ "$response" = "retry" ] && { ssh -i "$SSH_KEY" azureuser@$client_ip "curl -X POST 'http://localhost:5000/stop'" 2>/dev/null; continue; } || { retry_test=false; ((test_number++)); continue 2; }
                fi
                
                echo "Stopping CLIENT capture..."
                CLIENT_PCAP_PATH=$(ssh -i "$SSH_KEY" azureuser@$client_ip "curl -X POST 'http://localhost:5000/stop'" 2>/dev/null | grep -oE '/var/log/rtc/[^"]+')
                
                if [ -z "$CLIENT_PCAP_PATH" ]; then
                    echo "❌ ERROR: Failed to stop CLIENT capture"
                    read -p "Type 'retry' or ENTER to skip: " response
                    [ "$response" = "retry" ] && continue || { retry_test=false; ((test_number++)); continue 2; }
                fi
                
                # Download both PCAPs
                HOST_OUTPUT_FILE="$OUTPUT_DIR/test_${test_number}_${host_vpn}_to_${client_vpn}_host.pcap"
                CLIENT_OUTPUT_FILE="$OUTPUT_DIR/test_${test_number}_${host_vpn}_to_${client_vpn}_client.pcap"
                
                echo "Downloading HOST PCAP..."
                scp -i "$SSH_KEY" azureuser@$host_ip:$HOST_PCAP_PATH "$HOST_OUTPUT_FILE" 2>/dev/null
                
                if [ ! -f "$HOST_OUTPUT_FILE" ]; then
                    echo "❌ ERROR: Failed to download HOST PCAP"
                    read -p "Type 'retry' or ENTER to skip: " response
                    [ "$response" = "retry" ] && continue || { retry_test=false; ((test_number++)); continue 2; }
                fi
                
                echo "Downloading CLIENT PCAP..."
                scp -i "$SSH_KEY" azureuser@$client_ip:$CLIENT_PCAP_PATH "$CLIENT_OUTPUT_FILE" 2>/dev/null
                
                if [ ! -f "$CLIENT_OUTPUT_FILE" ]; then
                    echo "❌ ERROR: Failed to download CLIENT PCAP"
                    read -p "Type 'retry' or ENTER to skip: " response
                    [ "$response" = "retry" ] && continue || { retry_test=false; ((test_number++)); continue 2; }
                fi
                
                # Save to CSV
                TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
                echo "$test_number,$host_vpn,$client_vpn,$host_ip,$client_ip,$HOST_OUTPUT_FILE,$CLIENT_OUTPUT_FILE,NO,$TIMESTAMP" >> "$RESULTS_CSV"
                
                echo ""
                echo "✅ Test $test_number complete!"
                echo "   Host PCAP: $(basename $HOST_OUTPUT_FILE)"
                echo "   Client PCAP: $(basename $CLIENT_OUTPUT_FILE)"
            fi
            
            echo ""
            
            save_progress "$test_number"
            
            ssh -i "$SSH_KEY" azureuser@$host_ip "sudo iptables -Z" 2>/dev/null
            [ "$SAME_VM" = false ] && ssh -i "$SSH_KEY" azureuser@$client_ip "sudo iptables -Z" 2>/dev/null
            
            retry_test=false
            ((test_number++))
        done
    done
    
    echo "✅ Completed all 13 tests for HOST VPN: $host_vpn"
    echo "   Progress: $((test_number - 1))/169"
done

echo ""
echo "🎉 ALL 169 DUAL-CAPTURE TESTS COMPLETE! 🎉"
rm -f "$PROGRESS_FILE"

