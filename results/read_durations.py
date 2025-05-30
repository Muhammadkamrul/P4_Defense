import subprocess
import pandas as pd

THRIFT_PORT = 9090
OUTPUT_FILE = "../csv/durations.csv"
REGISTER_NAME = "ingress_packet_processing_durations_reg"

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
            csv_list_values = [value for value in csv_list if int(value) != 0]
            return csv_list_values
        else:
            # Print the error if the command fails
            print("Error executing command:")
            print(result.stderr)
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # Read the values from the register
    durations_list = read_register(REGISTER_NAME)

    # convert the duration list from micro seconds to milliseconds
    # duration_list = [int(duration) / 1000 for duration in duration_list]

    # Write the values to an excel file
    # Create a dictionary with the register names and their corresponding values
    data = {
        "Packet Number": [i for i in range(len(durations_list))],
        "Ingress Prossessing Duration": durations_list,
    }

    # Convert the dictionary to a DataFrame
    df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in data.items()]))

    # Write the DataFrame to a csv file
    df.to_csv(OUTPUT_FILE, index=False)

    print(f"Values written to {OUTPUT_FILE}.")