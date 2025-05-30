#!/bin/bash

# Check if PID is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <first host name>"
    exit 1
fi

# Base PID from the argument
base_pid=$(ps aux | grep "mininet:$1" | grep -v grep | awk '{print $2}' | head -n 1)

# List of host PIDs based on the formula: base_pid, base_pid+2, base_pid+4
host_pids=($(seq $((base_pid )) 2 $((base_pid + 4))))


# Define the path to the python script and the python interpreter
script_path="send_int_tcp_flood.py"
python_interpreter="/home/smartnic/p4dev-python-venv/bin/python"


# Execute the script on each host using mnexec
for host_pid in "${host_pids[@]}"; do
    # Extract the IPv6 link local address 
    ipv6_addr=$(mnexec -a $host_pid ip -6 addr show eth0 | grep -oP '(?<=inet6 )fe80:[0-9a-fA-F:]+/\d+')

    # Check if an IPv6 address was found
    if [ -z "$ipv6_addr" ]; then
        echo "Error: No valid IPv6 address starting with 2001 found for host with PID $host_pid."
        exit 1
    fi

    echo "Using IPv6 address $ipv6_addr for host with PID $host_pid..."

    # Execute the script on the host
    mnexec -a $host_pid nohup $python_interpreter $script_path > /dev/null 2>&1 &
done

echo "Script executed on all specified hosts."
