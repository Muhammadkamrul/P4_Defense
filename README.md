# P4_Defense
# P4-Network-Defense
## Table of Contents
- Project Summary
- Prerequisites
- Before Starting
- File List
- How to Run
    - Existing P4 Programs
    - Preperation
    - Compilation and Running
    - Executing The Experiments & Getting The Results
    - Terminating The Mininet Network
## Project Summary
We are developing a defence system against flooding and spoofing attacks in a P4 switch. Our work explores two approaches: a P4 rule-based approach, which uses predefined rules to detect and mitigate attacks, and an ML-based approach, where we generate a surrogate decision tree from the ML model and apply the extracted rules in a P4 program for real-time packet processing. 
## Prerequisites
- [P4 Development Environment](https://github.com/p4lang/tutorials?tab=readme-ov-file#obtaining-required-software)
## Before Starting
In order to everything to run as expected, do the following before starting anything.  
Go to each file that has name that starts with `run_` inside the `.../traffic/` directory and change the value of the `python_interpreter` variable to the full (absolute) path of the P4-Dev Python binary.
## File List
- `.../csv/`: Contains the ingress processing durations for the Rule-Based P4 Experiments.
- `.../generated_code/`: Contains part P4 files, which are files containing P4 code that is injected inside other P4 code using `#include`.
    - Currently only contains part P4 files for `ml.p4`.
- `.../results/`: Contains Python scripts that are used to write the results of experiments.
    - `.../results/read_features.py`: Creates a `features.csv` file in `.../csv/` that contains the values of the extracted ML features for all packets recieved by the victim switch, i.e., `s1`, in the currently running `ml.p4` program. It is mainly used for debugging.
        - If new features has been added to be extracted in the `ml.p4`, the new features will not be displayed in the CSV file unless they are added to the `metadata_reg` register in the P4 code and the `read_features.py` file is modified to parse the register correctly.
    - `.../results/read_ml_drop.py`: Prints a simple report of the dropped packets and their types for the currently running P4 Switch running the `ml.p4` program.
    - `.../results/read_rule_based_drop.py`: Prints a simple report of the dropped packets and their types for the currently running P4 Switch running the `defense.p4` program.
- `.../topo/`: Contains the information about the topology of the experiments.
    - `.../topo/Experiment Topology.png`: An image of the topology.
    - `.../topo/topo.json`: Contains the details of the topology such as host details (host names, and MAC, IPv4, and IPv6 addresses, neighbor cache entries, etc...), switch details (switch names, switch runtime json files), and link details (host-switch and switch-switch links).
    - `.../topo/s[x]-runtime[-type].json`: Specifies what compiled P4 program will switch `s[x]` run, as well as populating the tables of that switch. `s1` (the victim switch) has multiple types:
        - `s1-runtime-m.json`: Must be used to run the compiled `multicast.p4` program.
        - `s1-runtime-ml-plain.json`: Must be used to run the compiled `ml.p4` program. Use this file when using `ml.p4` without any feature extraction, i.e., only packet forwarding.
        - `s1-runtime-ml.json`: Must be used to run the compiled `ml.p4` program. Use this file when using `ml.p4` with feature extraction, i.e., feature extraction + packet forwarding.
        - `s1-runtime-rule-based.json`: Must be used to run the compiled `defense.p4` program.
        - `s1-runtime-test.json`: Must be used to run the compiled `test.p4` program.
- `.../traffic/`: Contains all of the scripts used to generate traffic for the experiments.
    - `.../traffic/experiment scripts.txt`: Contains the order of the scripts to execute for each experiment.
    - `.../traffic/send_[traffic_type].py`: Used to send traffic of type `[traffic_type]` from a single Mininet host.
    - `.../traffic/run_[traffic_type].sh`: Used to run `send_[traffic_type].py` from multiple Mininet hosts at the same time.
- `.../util/`: Contains utility scripts
    - `.../util/modified_rules.txt`: Contains the surrogate rules for an ML model in Python If syntax. It is generated from the ML model.
    - `.../util/convert_to_p4_if.py`: Used to convert the `modified_rules.txt` file from Python If syntax to P4 If syntax and saves it in `.../generated_code/ml_surrogate_model_rules.p4.part`.
    - `.../util/generate_topo.py`: Used to automatically generate the complex topology that is used in this project's experiments.
- `.../Makefile`: Used to run the P4 switches and the Mininet network defined in `.../topo/topo.json`. It is also used to clean the P4 & Mininet environment.
- `.../defense.p4`: The P4 program for the Rule-Based Defense System.
    - If the filename is `defense.p4.bak`, it means that it will not be compiled.
- `.../ml.p4`: The P4 program for the ML in P4 approach.
    - If the filename is `ml.p4.bak`, it means that it will not be compiled.
- `.../multicast.p4`: A P4 program that only forwards packets (No defense). It is always used in all switches except `s1`, i.e., the victim switch, and only sometimes used in `s1`.
- `.../test.p4`: A P4 program used for debugging.
    - If the filename is `test.p4.bak`, it means that it will not be compiled.
## How to Run
### Existing P4 Programs
- **Rule-Based Program**
    - External Spoofing Module -> Internal Spoofing Module -> External Flooding Module -> Internal Flooding Module -> Packet Forwarding
    - **P4 Source Code File:** `.../defense.p4`
    - **Switch Runtime JSON File:** `.../topo/s1-runtime-rule-based.json`
- **ML Program With Feature Extraction**
    - Feature Extraction -> Applying Surrogate Tree Rules -> Logging Features Extracted -> Packet Forwarding
    - **P4 Source Code File:** `.../ml.p4`
    - **Switch Runtime JSON File:** `.../topo/s1-runtime-ml.json`
- **ML Program Without Feature Extraction**
    - Only does Packet Forwarding (Mainly used for debugging)
    - **P4 Source Code File:** `.../ml.p4`
    - **Switch Runtime JSON File:** `.../topo/s1-runtime-ml-plain.json`
- **Simple Forwarding Program**
    - Only does Packet Forwarding
    - **P4 Source Code File:** `.../multicast.p4`
    - **Switch Runtime JSON File:** `.../topo/s1-runtime-m.json`
- **Testing Program**
    - Only used for debugging and testing
    - **P4 Source Code File:** `.../test.p4`
    - **Switch Runtime JSON File:** `.../topo/s1-runtime-test.json`
### Preperation
In this section, we will prepare according to the P4 program that we want to execute in `s1`.  
> [!NOTE]
> The steps in this section must be done everytime you want to change the P4 program to be executed in `s1`
- Make sure that the **P4 Source Code File** to be executed in `s1` ends in `.p4`, i.e., does not end with `.p4.bak`.
- In `.../topo/topo.json`, modify the JSON value in `switches`->`s1`->`runtime_json` to the appropriate **Switch Runtime JSON File** according to the P4 program to be executed in `s1`.
- In `.../Makefile`, modify the line that contains `run_args += -j $(BUILD_DIR)/[compiled_p4_program].json`, where `[compiled_p4_program]` should be **P4 Source Code File** without the `.p4` suffix.
### Compilation and Running
In this section, we will compile and run the P4 program we prepared in the Preperation step.  
  
From the same directory as the `Makefile` file, run `make clean` followed by `make run`    
`make clean`: Cleans the environment by removing files related to the previous environment  
`make run`: Does the following in order
1. Creates the directories `.../build/`, `.../logs/`, and `.../pcaps/`.
    - `.../build/` contains the compiled P4 programs (`.json`) and the P4info files (`.p4.p4info.txt`).
    - `.../logs/` contains the log files for all switches.
    - `.../pcaps/` contains the `.pcap` files for all ports for all switches.
2. Compiles all files (in the same directory as `Makefile` and all child directories) that end in `.p4`.
3. Creates an empty Mininet network.
4. Starts all switches that were defined in `.../topo/topo.json` and load a placeholder P4 program in all of them.
5. Uses the switch runtime JSON files to:
    - Load the correct (compiled) P4 program into each switch.
    - Populate the tables in the P4 program for each switch.
6. Creates all Mininet hosts according to `.../topo/topo.json`.
7. Creates the Mininet network links according to `.../topo/topo.json`.
8. Starts the Mininet CLI.
### Executing The Experiments & Getting The Results
In this section, we will run the traffic sending Python scripts to execute the experiments on the currently running Mininet network.  
1. **Preparing Wireshark**: Run Wireshark and make sure it is capturing the traffic from the `s1-eth6` interface, i.e., the network link connected to the victim.
2. **Sending Traffic**: The details on what traffic sending scripts to execute and how to execute them is described in `.../traffic/experiment scripts.txt`.  
3. **Wait for the traffic sending scripts to complete**: you can know when you see that the Wireshark packet counter (in the bottom right of the window) stopped increasing.
4. **Get The Results**:
    - The Wireshark capture contains all of the packets that exited the switch towards the victim.
    - (After all experiment traffic stops,) Use the python scripts `.../results/read_rule_based_drop.py` (if the Rule-Based Program was loaded) or `.../results/read_ml_drop.py`(if the ML Program was loaded) to print a simple report of the dropped packets (inside the switch) and their types.

> [!IMPORTANT]
> After finishing **each** experiment and getting its results, you must exit the Mininet network and clean the environment using `make clean`. After that, you may start the network again using `make run` if there is another experiment to run.
### Terminating The Mininet Network
To exit the Mininet CLI, type `exit` or press `CTRL+d`.  
It is recommended to clean the environment after exiting the Mininet CLI by entering the command `make clean`.
