#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <topology_number> <convergence_time>"
    exit 1
fi
topo_num="$1"
c_time="$2"

# Function to execute the turn-off script for an interface
turn_off_interface() {
    local script_name=$1
    echo "Turning off interface using script: $script_name"
    bash ./"$script_name" $topo_num  # Assuming the turn-off scripts are in the same directory
}

# Function to execute the turn-on script for an interface
turn_on_interface() {
    
    local turn_off_script=$1
    local script_name=$(echo "$turn_off_script" | sed 's/turn_off/turn_on/;s/.sh//')


    echo "Turning on interface using script: $script_name.sh"
    bash ./"$script_name.sh" $topo_num  # Assuming the turn-on scripts are in the same directory
}

# Function to ping an IP address for 10 seconds
ping_all_ips() {
    local interface_script=$1
    turn_off_interface "$interface_script"
    sleep $c_time
    bash ping_all_ips.sh $topo_num
    turn_on_interface "$interface_script"
    sleep $c_time
}



# List of interface scripts to turn off and on
interface_scripts=(
    "turn_off_v1-v2.sh"
    "turn_off_v1-v3.sh"
    "turn_off_v2-v3.sh"
    # Add more interface scripts as needed
)

# Loop through each interface script
for script in "${interface_scripts[@]}"; do
    # Extract the interface name from the script name
    interface_name=$(echo "$script" | sed 's/turn_off_//;s/turn_on_//;s/.sh//')
    
    # Ping using the corresponding interface script
    
    ping_all_ips "$script"

done
