import subprocess
import pandas as pd

THRIFT_PORT = 9090
REGISTER_NAME = "drop_counter_reg"
DROP_COUNTER_LABLES = (
    ("External Spoofing (hop count)", "TCP attack (other)"),
    ("External Spoofing (suspicious counter)", "TCP attack (other)"),
    ("Internal Spoofing (src addr port mapping)", "N/A"),
    ("External Flooding (prefix packet counting)", "TCP attack (other)"),
    ("Internal Flooding (unicast flow packet counting)", "NS"),
    ("Internal Flooding (multicast flow packet counting)", "NA (Not used)"),
    ("Internal Flooding (unicast flow packet counting)", "TCP attack (other)"),
    ("External Flooding (prefix packet counting)", "TCP benign (tcp tsval 1000)"),
    ("Internal Flooding (unicast flow packet counting)", "TCP benign (tcp tsval 1000)"),
    ("External Spoofing (hop count)", "TCP benign (tcp tsval 1000)"),
    ("External Spoofing (suspicious counter)", "TCP benign (tcp tsval 1000)")
)

def read_register(register_name: str) -> list[str]:
    """
    Read all values from a specified register in the P4 program using simple_switch_CLI.

    Returns:
        list[str]: List of values read from the register.
    """
    # Define the command to be executed in simple_switch_CLI
    command = f"register_read {register_name}"

    # Construct the full command to run simple_switch_CLI with the specified command
    cli_command = f'echo "{command}" | simple_switch_CLI --thrift-port {THRIFT_PORT}'

    # Execute the command using subprocess
    try:
        result = subprocess.run(cli_command, shell=True, text=True, capture_output=True)
        if result.returncode == 0:
            # Print the output of the command
            print("Command executed successfully:")

            # Parse the output to get the values from the register
            cmd = result.stdout.split("\n")[3]
            csv_list = cmd.split(": ")[1].split("= ")[1].split(", ")
            csv_list_values = [value for value in csv_list] # You may add a filtering condition here
            return csv_list_values
        else:
            # Print the error if the command fails
            print("Error executing command:")
            print(result.stderr)
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # Read the values from the registers
    drop_counters = read_register(REGISTER_NAME)
    for i, drop_counter in enumerate(drop_counters):
        # format the output to be more readable
        print(f"\t{i:<3}{DROP_COUNTER_LABLES[i][0]:<55}{DROP_COUNTER_LABLES[i][1]:<30}: {drop_counter}")