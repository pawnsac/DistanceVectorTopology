#!/bin/bash

# Check if the input file is provided
if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <toplogy_number>"
    exit 1
fi

input_file="vnltopo$1.iplist"

# Read IP addresses and their names from the input file
declare -A ip_interfaces
while IFS='=' read -r interface ip; do
    ip_interfaces["$ip"]="$interface"
done < "$input_file"

# Variable to count successful pings
success_count=0

# Function to ping an IP address for 5 seconds
ping_ip_for_5_seconds() {
    local ip=$1
    local interface=${ip_interfaces[$ip]}

    if [ -n "$interface" ]; then
        echo "Pinging $ip on interface $interface for 5 seconds..."
        if ping -c 5 "$ip"; then
            echo "Pinged $ip successfully on interface $interface."
            ((success_count++))
        else
            echo "Failed to ping $ip on interface $interface."
        fi
    else
        echo "Interface not defined for IP $ip."
    fi
}

# Loop through each IP address and ping for 5 seconds
for ip in "${!ip_interfaces[@]}"; do
    ping_ip_for_5_seconds "$ip"
done

# Print the number of successful pings
echo -e "\n\n\nNumber of successful pings: $success_count/${#ip_interfaces[@]}\n\n\n"
