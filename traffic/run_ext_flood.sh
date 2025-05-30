#!/bin/bash

# Check if PID is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <first host name>"
    exit 1
fi

# Get the base PID (first matching process)
base_pid=$(ps aux | grep "mininet:$1" | grep -v grep | awk '{print $2}' | head -n 1)

# Check if base_pid is valid
if [ -z "$base_pid" ]; then
    echo "Error: Could not find the process for mininet:$1"
    exit 1
fi

# Generate host PIDs: base_pid, base_pid+2, base_pid+4, ..., base_pid+8
host_pids=($(seq "$base_pid" 2 "$((base_pid + 8))"))

# Define the path to the Python script and the Python interpreter
script_path="send_ext_syn_flood.py"
python_interpreter="/home/smartnic/p4dev-python-venv/bin/python"

# Execute the script on each host using mnexec
for host_pid in "${host_pids[@]}"; do
    # Extract the IPv6 link-local address
    ipv6_addr=$(mnexec -a "$host_pid" ip -6 addr show eth0 | awk '/inet6 2001:/ {print $2; exit}')

    # Check if an IPv6 address was found
    if [ -z "$ipv6_addr" ]; then
        echo "Error: No valid IPv6 address starting with 2001 found for host with PID $host_pid."
        continue  # Skip this host and continue with the next one
    fi

    echo "Using IPv6 address $ipv6_addr for host with PID $host_pid..."

    # Execute the script on the host (append logs for debugging)
    mnexec -a "$host_pid" nohup "$python_interpreter" "$script_path" > /dev/null 2>&1 &

    echo "Script started on host PID $host_pid (Logs: /home/mez/mnexec_$host_pid.log)"
done

echo "Script execution initiated on all specified hosts."
