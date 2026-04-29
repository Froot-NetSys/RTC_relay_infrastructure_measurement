#!/bin/bash

echo "=========================================="
echo "STARTING 169 WHATSAPP TESTS"
echo "=========================================="
echo ""

# List all devices to find UDIDs
echo "Finding connected devices..."
xcrun xctrace list devices 2>&1 | grep "iPhone"

echo ""
read -p "Enter Host iPhone UDID (copy from above): " HOST_DEVICE
read -p "Enter Client iPhone UDID (copy from above): " CLIENT_DEVICE

echo ""
echo "Host Device: $HOST_DEVICE"
echo "Client Device: $CLIENT_DEVICE"
echo ""

# Paths to projects
HOST_PROJECT="$HOME/Documents/rtcproxy/WhatsAppHost/WhatsAppHost.xcodeproj"
CLIENT_PROJECT="$HOME/Documents/rtcproxy/WhatsAppClient/WhatsAppClient.xcodeproj"

echo "Starting tests in 5 seconds..."
sleep 5

# Start HOST test in background
echo "Launching HOST test..."
xcodebuild test \
    -project "$HOST_PROJECT" \
    -scheme WhatsAppHost \
    -destination "platform=iOS,id=$HOST_DEVICE" \
    -allowProvisioningUpdates \
    -only-testing:WhatsAppHostUITests/WhatsAppHostUITests/testAutomatedWhatsAppCalls &

HOST_PID=$!

# Wait 1 second, then start CLIENT test
sleep 1

echo "Launching CLIENT test..."
xcodebuild test \
    -project "$CLIENT_PROJECT" \
    -scheme WhatsAppClient \
    -destination "platform=iOS,id=$CLIENT_DEVICE" \
    -allowProvisioningUpdates \
    -only-testing:WhatsAppClientUITests/WhatsAppClientUITests/testAcceptWhatsAppCalls &

CLIENT_PID=$!

echo ""
echo "Both tests running!"
echo ""

# Wait for both to complete
wait $HOST_PID
HOST_EXIT=$?
wait $CLIENT_PID
CLIENT_EXIT=$?

echo ""
echo "=========================================="
echo "TESTS COMPLETE!"
echo "Host exit code: $HOST_EXIT"
echo "Client exit code: $CLIENT_EXIT"
echo "=========================================="
