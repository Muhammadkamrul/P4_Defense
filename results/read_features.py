import subprocess
import pandas as pd

THRIFT_PORT = 9090
OUTPUT_FILE = "./csv/features.csv"
REGISTER_NAME = "metadata_reg"

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
    # Read the values from the register
    metadata_list = read_register("metadata_reg")
    
    # Initialize 11 empty lists
    list1, list2, list3, list4, list5, list6, list7, list8, list9, list10, list11, list12, list13, list14 = ([] for _ in range(14))

    # List of lists for easy access
    lists = [list1, list2, list3, list4, list5, list6, list7, list8, list9, list10, list11, list12, list13, list14]

    # Distribute elements into the lists
    for index, value in enumerate(metadata_list):
        lists[index % 14].append(value)

    # convert the duration list from micro seconds to milliseconds
    # duration_list = [int(duration) / 1000 for duration in duration_list]

    # Write the values to an excel file
    # Create a dictionary with the register names and their corresponding values
    data = {
        "Packet ID": lists[0],
        "Source Address": lists[1],
        "Hop Count": lists[2],
        "New Addresses Seen": lists[3],
        "Port": lists[4],
        "Protocol": lists[5],
        "flow_window_packet_count": lists[6],
        "prefix_window_packet_count": lists[7],
        "flow_window_start_time 1": lists[8],
        "flow_window_start_time 2": lists[9],
        "flow_window_start_time 3": lists[10],
        "prefix_window_start_time 1": lists[11],
        "prefix_window_start_time 2": lists[12],
        "prefix_window_start_time 3": lists[13],
    }

    # Convert the dictionary to a DataFrame
    df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in data.items()]))

    # Write the DataFrame to a csv file
    df.to_csv(OUTPUT_FILE, index=False)

    print(f"Values written to {OUTPUT_FILE}.")