#!/usr/bin/env python3
import argparse
import time
import os
import subprocess
import logging
import sys
import re

#Usage: generate_horcm_by_ctgs.py -c 10.0.0.13 10.0.0.11 10.0.0.15 -u maintenance maintenance maintenance -p raid-maintenance raid-maintenance raid-maintenance -i 880 881 882 -n 44880 44881 44882

# Create a custom logger
logger = logging.getLogger("logger")
# Set the level of this logger. INFO means that it will handle all messages with a level of INFO and above
logger.setLevel(logging.DEBUG)
# Create handlers
c_handler = logging.StreamHandler()
f_handler = logging.FileHandler('generate_horcm_by_ctgs.log')
c_handler.setLevel(logging.DEBUG)
f_handler.setLevel(logging.DEBUG)
# Create formatters and add it to handlers
c_format = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
f_format = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
c_handler.setFormatter(c_format)
f_handler.setFormatter(f_format)
# Add handlers to the logger
logger.addHandler(c_handler)
logger.addHandler(f_handler)

def check_equal_length(*lists):
    return all(len(lst) == len(lists[0]) for lst in lists)
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--connectionstrings", dest="connectionstrings", nargs='+', help="Enter connection strings, either IP addresses or CMDEV strings, e.g. 10.0.0.13 10.0.0.11 10.0.0.15")
    parser.add_argument("-u", "--usernames", dest="usernames", nargs='+', help="Enter usernames, e.g. maintenance maintenance maintenance")
    parser.add_argument("-p", "--passwords", dest="passwords", nargs='+', help="Enter passwords, e.g. raid-maintenance raid-maintenance raid-maintenance")
    parser.add_argument("-i", "--instances", dest="instances", nargs='+', help="Enter HORCM instances, e.g. 880 881 882")
    parser.add_argument("-n", "--numbersofudpports", dest="numbersofudpports", nargs='+', help="Enter UDP port numbers, e.g. 44880 44881 44882")
    arguments = parser.parse_args()
    if not arguments.connectionstrings:
        parser.exit("[-] Missing data: connectionstrings.")
    elif not arguments.usernames:
        parser.exit("[-] Missing data: usernames.")
    elif not arguments.passwords:
        parser.exit("[-] Missing data: passwords.")
    elif not arguments.instances:
        parser.exit("[-] Missing data: instances")
    elif not arguments.numbersofudpports:
        parser.exit("[-] Missing data: numbersofudpports.")
    if not check_equal_length(arguments.connectionstrings, arguments.usernames, arguments.passwords, arguments.instances, arguments.numbersofudpports):
        parser.exit("[-] Number of values of each arguments argument much be equal to each other")
    return arguments

def is_valid_ip(ip):
    logger.info("Function execution started")
    start_time = time.time()
    pattern = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return bool(pattern.match(ip))


def get_horcm_path(os_type):
    logger.info("Function execution started")
    start_time = time.time()
    if os_type == "win32":
        windir = os.environ.get('SystemRoot')
        full_horcmpath = windir + "\\"
        logger.info(
            "queried HORCM directory location, returned: " + full_horcmpath + " horcmXXX.conf files will be created here")
    elif os_type == "linux":
        full_horcmpath = "/etc/"
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return full_horcmpath

def create_horcm_file(horcm_instance, path, storage_ip, udpport):
    logger.info("Function execution started")
    start_time = time.time()
    horcm_file_full_path = path + "horcm" + horcm_instance + ".conf"
    with open(horcm_file_full_path, 'w') as horcm_file:
        horcm_file.write("HORCM_MON" + '\n')
        horcm_file.write("#ip_address" + '\t' + "service" + '\t' + "poll(10ms)" + '\t' + "timeout(10ms)" + '\n')
        horcm_file.write("localhost" + '\t' + udpport + '\t' + "1000" + '\t\t' + "3000" + '\n\n\n')
        horcm_file.write("HORCM_CMD" + '\n')
        horcm_file.write("#dev_name" + '\t' + "dev_name" + '\t' + "dev_name)" + '\t' + "dev_name" + '\n')
        if is_valid_ip(storage_ip):
            horcm_file.write("\\\\.\\IPCMD-" + storage_ip + "-31001" + '\n')
        else:
            horcm_file.write(storage_ip + '\n')
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")


def shutdown_horcm_instance(horcm_instance, path, os_type):
    logger.info("Function execution started")
    start_time = time.time()
    horcm_file_full_path = path + "\\" + "horcm" + horcm_instance + ".conf"
    os.environ['HORCM_CONF'] = horcm_file_full_path
    os.environ['HORCMINST'] = horcm_instance
    os.environ['HORCM_EVERYCLI'] = "1"
    if os_type == "win32":
        subprocess.run(["horcmshutdown"])
    elif os_type == "linux":
        subprocess.run(["horcmshutdown.sh"])

    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")


def start_horcm_instance(horcm_instance, path, os_type):
    logger.info("Function execution started")
    start_time = time.time()
    try:
        shutdown_horcm_instance(horcm_instance, path, os_type)
    except:
        logger.info("Could not shutdown HORCM instance, might be down already")
    horcm_file_full_path = path + "horcm" + horcm_instance + ".conf"
    os.environ['HORCM_CONF'] = horcm_file_full_path
    os.environ['HORCMINST'] = horcm_instance
    os.environ['HORCM_EVERYCLI'] = "1"
    if os_type == "win32":
        subprocess.run(["horcmstart"])
    elif os_type == "linux":
        subprocess.run(["horcmstart.sh"])
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")

def raidcom_login(horcm_instance, username, password):
    logger.info("Function execution started")
    start_time = time.time()
    subprocess.run(["raidcom", "-login", username, password, "-I" + horcm_instance])
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")

def get_storage_serial_number(horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    get_resource = []
    get_resource = subprocess.check_output(
        ["raidcom", "get", "resource", "-fx", "-key", "opt", "-I" + horcm_instance]).decode().splitlines()
    serial = get_resource[1].split()[5].strip()
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return serial

def init_main_dict(connectionstrings_list, usernames_list, passwords_list, instances_list, numbersofudpports_list):
    # create main dictionary in which the key is the storage system serial number.
    # structure example: {'560311': {'connection_string': '10.0.0.13', 'username': 'maintenance', 'password': 'raid-maintenance', 'horcm_instance': '880', 'horcm_udp_port': '44880'}, '540491': {'connection_string': '10.0.0.11', 'username': 'maintenance', 'password': 'raid-maintenance', 'horcm_instance': '881', 'horcm_udp_port': '44881'}, '533610': {'connection_string': '10.0.0.15', 'username': 'maintenance', 'password': 'raid-maintenance', 'horcm_instance': '882', 'horcm_udp_port': '44882'}}
    main_dict = {}
    for i, connection_string in enumerate(connectionstrings_list):
        create_horcm_file(instances_list[i], horcm_path, connectionstrings_list[i], numbersofudpports_list[i])
        start_horcm_instance(instances_list[i], horcm_path, os_type)
        raidcom_login(instances_list[i], usernames_list[i], passwords_list[i])
        serial = get_storage_serial_number(instances_list[i])
        main_dict[serial] = {}
        # main_dict[serial].append(connectionstrings_list[i])
        # main_dict[serial].append(usernames_list[i])
        # main_dict[serial].append(passwords_list[i])
        # main_dict[serial].append(instances_list[i])
        # main_dict[serial].append(numbersofudpports_list[i])
        main_dict[serial]["connection_string"] = connectionstrings_list[i]
        main_dict[serial]["username"] = usernames_list[i]
        main_dict[serial]["password"] = passwords_list[i]
        main_dict[serial]["horcm_instance"] = instances_list[i]
        main_dict[serial]["horcm_udp_port"] = numbersofudpports_list[i]
    return main_dict

#Write all the user input into variables
user_input = get_arguments()
connectionstrings_list = user_input.connectionstrings
usernames_list = user_input.usernames
passwords_list = user_input.passwords
instances_list = user_input.instances
numbersofudpports_list = user_input.numbersofudpports

#Write os_type and horcm_path into variables
os_type = sys.platform
horcm_path = get_horcm_path(os_type)

#Init main dict:
main_dict = init_main_dict(connectionstrings_list, usernames_list, passwords_list, instances_list, numbersofudpports_list)
print(main_dict)
print('\n')
for sn in main_dict:
    print(sn)
    print(main_dict[sn])