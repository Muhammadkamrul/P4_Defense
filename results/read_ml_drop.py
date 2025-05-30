import subprocess

THRIFT_PORT = 9090
REGISTER_NAME = "drop_counter_reg"
# write the drop counters according to the following
# index Attack Label			Packet Type
# ----------------------------------------------
# 0	    External Spoofing		TCP benign (tcp tsval 1000)
# 1	    External Spoofing		TCP attack (other tcp)
# 2	    External Spoofing		NS (all NS)

# 3	    Internal Spoofing 		TCP benign (tcp tsval 1000)
# 4	    Internal Spoofing 		TCP attack (other tcp)
# 5	    Internal Spoofing		NS (all NS)

# 6	    External Flooding		TCP benign (tcp tsval 1000)
# 7	    External Flooding		TCP attack (other tcp)
# 8	    External Flooding		NS (all NS)

# 9	    Internal Flooding		TCP benign (tcp tsval 1000)
# 10	Internal Flooding		TCP attack (other tcp)
# 11	Internal Flooding		NS (all NS)

# 12	External Flooding + Spoofing	TCP benign (tcp tsval 1000)
# 13	External Flooding + Spoofing	TCP attack (other tcp)
# 14	External Flooding + Spoofing	NS (all NS)

DROP_COUNTER_LABLES = (
    ("External Spoofing", "TCP benign (tcp tsval 1000)"),
    ("External Spoofing", "TCP attack (other tcp)"),
    ("External Spoofing", "NS (all NS)"),

    ("Internal Spoofing", "TCP benign (tcp tsval 1000)"),
    ("Internal Spoofing", "TCP attack (other tcp)"),
    ("Internal Spoofing", "NS (all NS)"),

    ("External Flooding", "TCP benign (tcp tsval 1000)"),
    ("External Flooding", "TCP attack (other tcp)"),
    ("External Flooding", "NS (all NS)"),

    ("Internal Flooding", "TCP benign (tcp tsval 1000)"),
    ("Internal Flooding", "TCP attack (other tcp)"),
    ("Internal Flooding", "NS (all NS)"),

    ("External Flooding + Spoofing", "TCP benign (tcp tsval 1000)"),
    ("External Flooding + Spoofing", "TCP attack (other tcp)"),
    ("External Flooding + Spoofing", "NS (all NS)")
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

            # Parse the output to get the values from the register (excluding the zeros)
            cmd = result.stdout.split("\n")[3]
            csv_list = cmd.split(": ")[1].split("= ")[1].split(", ")
            csv_list_values = [value for value in csv_list]
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
        # print a new line after each group of 3 counters
        if i % 3 == 0 and i != 0:
            print()
        # format the output to be more readable
        print(f"\t{i:<3}{DROP_COUNTER_LABLES[i][0]:<35}{DROP_COUNTER_LABLES[i][1]:<30}: {drop_counter}")
        