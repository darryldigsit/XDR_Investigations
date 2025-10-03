#!/bin/bash

# Linux XDR Triggers - for security tool/EDR/NDR/NVM visibility testing
# Each section mimics common "malicious" activity patterns, but is benign.

function edr_trigger {
    echo ""
    echo "The following command will attempt to read protected process (like /etc/shadow), but will be denied."
    echo ""

    cat /etc/shadow > shadow_dump.txt 2>/dev/null

    if [[ $? -ne 0 ]]; then
        echo "/etc/shadow dump attempt failed (as expected, unless run as root)."
    else
        echo "WARNING: /etc/shadow was readable (unexpected)."
    fi
    echo "Completed Successfully"
}

function nvm_trigger {
    echo ""
    echo "This command downloads a public image and deletes it immediately."
    echo ""

    TMPIMG="/tmp/LinuxXDRImage.jpg"
    curl -s -o "$TMPIMG" "https://www.cisco.com/content/dam/cisco-cdc/site/images/heroes/homepage/2025/nvidia-cisco-ai-2400x1028.jpg"
    rm -f "$TMPIMG"
    echo "Completed Successfully"
}

function ndr_trigger {
    echo ""
    echo "This script runs a TCP port scan of 192.168.3.1-10, ports 22,80,443. Results print to screen."
    echo ""

    for ip in {1..10}; do
        target="192.168.3.$ip"
        for port in 22 80 443; do
            timeout 1 bash -c "</dev/tcp/$target/$port" 2>/dev/null &&
                echo "Port $port open on $target" ||
                echo "Port $port closed on $target"
        done
    done
    echo "Completed Successfully"
}

function all_triggers {
    edr_trigger
    nvm_trigger
    ndr_trigger
}

function encoded_triggers {
    echo ""
    echo "This runs all triggers using base64 encoding and command masquerading for evasion-style testing."
    echo ""

    # EDR encoded
    echo "Y2F0IC9ldGMvc2hhZG93ID4gc2hhZG93X2R1bXAudHh0IDI+L2Rldi9udWxsCg==" | base64 -d | bash

    # NVM encoded
    echo "Y3VybCAtcyAtbyAvdG1wL0xpbnV4WERSSW1hZ2UuanBnICJodHRwczovL3d3dy5jaXNjby5jb20vY29udGVudC9kYW0vY2lzY28tY2RjL3NpdGUvaW1hZ2VzL2hlcm9lcy9ob21lcGFnZS8yMDI1L25]HZGlhLWNpc2NvLWFpLTI0MDB4MTAyOC5qcGciOyBybSAtZiAvdG1wL0xpbnV4WERSSW1hZ2UuanBnCg==" | base64 -d | bash

    # NDR encoded
    b64='Zm9yIGlwIGluIHsxLi4xMH07IHRhcmdldD0iMTkyLjE2OC4zLiR7aXB9IjsgZm9yIHBvcnQgaW4gMjIgODAgNDQzOyBkbwogICAgdGltZW91dCAxIGJhc2ggLWMgIjwvZGV2L3RjcC8kdGFyZ2V0LyRwb3J0IiAyPi9kZXYvbnVsbAogICAgJiYgZWNobyAiUG9ydCAkcG9ydCBvcGVuIG9uICR0YXJnZXQiIHx8IGVjaG8gIlBvcnQgJHBvcnQgY2xvc2VkIG9uICR0YXJnZXQiCmRvbmU='
    echo $b64 | base64 -d | bash

    echo "Completed Successfully"
}

while true; do
    clear
    echo "Choose an option:"
    echo "1) EDR trigger"
    echo "2) NVM trigger"
    echo "3) NDR trigger"
    echo "4) ALL 3"
    echo "5) All Encoded Triggers"
    read -rp "Enter your choice (1-5): " choice
    case $choice in
        1) edr_trigger ;;
        2) nvm_trigger ;;
        3) ndr_trigger ;;
        4) all_triggers ;;
        5) encoded_triggers ;;
        *) echo "Invalid choice. Please try again." ;;
    esac
    read -rp "Press Enter to continue..."
done
