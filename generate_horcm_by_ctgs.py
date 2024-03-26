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
def create_vsm_dict(horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    vsm_dict = {}
    get_resource = subprocess.check_output(
        ["raidcom", "get", "resource", "-fx", "-key", "opt", "-I" + horcm_instance]).decode().splitlines()
    for vsm in get_resource[1:]:
        splitter_by_2_spaces_or_more = re.split(r' {4,}', vsm)
        key = splitter_by_2_spaces_or_more[1].strip()
        value = splitter_by_2_spaces_or_more[0].strip()
        vsm_dict[key] = value
        # vsm_dict[vsm.split()[1].strip()] = vsm.split()[0].strip()
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return vsm_dict

def create_host_grp_array_of_arrays(horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    vsm_dict = create_vsm_dict(horcm_instance)
    array_of_ports = []
    array_of_host_grps = [['PORT', 'GID', 'PORT-GID', 'GROUP_NAME', 'Serial', 'HMD', 'HMO_BITs', 'VSM_NAME', 'VSM_ID']]
    ports = subprocess.check_output(["raidcom", "get", "port", "-fx", "-I" + horcm_instance])
    for port in ports.splitlines():
        port = port.decode()
        if "FIBRE" in port:
            array_of_ports.append(port.split()[0])
    array_of_unique_ports = set(array_of_ports)
    for port in array_of_unique_ports:
        for key in vsm_dict:
            get_host_grps_of_a_port = subprocess.check_output(
                ["raidcom", "get", "host_grp", "-port", port, "-fx", "-resource", key, "-I" + horcm_instance])
            get_host_grps_of_a_port = get_host_grps_of_a_port.splitlines()
            for host_grp in get_host_grps_of_a_port:
                host_grp = host_grp.decode()
                if not "GROUP_NAME" in host_grp:
                    host_grp = host_grp.split()
                    hmo = " ".join(host_grp[5:])
                    if host_grp[4] == "LINUX/IRIX":
                        host_grp[4] = "LINUX"
                    host_grp_concat_hmo = [host_grp[0], host_grp[1], host_grp[0] + "-" + host_grp[1], host_grp[2],
                                           host_grp[3], host_grp[4], hmo, vsm_dict[key], key]
                    array_of_host_grps.append(host_grp_concat_hmo)
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return array_of_host_grps

def get_ldev_list_mapped(horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    array_of_ldevs = []
    ldevs = subprocess.check_output(
        ["raidcom", "get", "ldev", "-ldev_list", "mapped", "-fx", "-key", "front_end", "-I" + horcm_instance])
    ldevs = ldevs.decode()
    # ldevs = re.sub(r" \|GAD","|GAD", ldevs)
    ldevs = ldevs.replace(" |GAD", "|GAD")
    ldevs = ldevs.splitlines()
    for ldev in ldevs:
        # ldev = ldev.decode()
        if not "VOL_TYPE" in ldev:
            ldev = ldev.split()
            array_of_ldevs.append(ldev)
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return array_of_ldevs

def output_horcm_text_data(horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    horcm_ldev = []
    get_ldev_list_mapped_output = []
    get_ldev_list_mapped_output = get_ldev_list_mapped(horcm_instance)
    for i in get_ldev_list_mapped_output:
        if re.search(r'HORC', i[7]) or re.search(r'GAD', i[7]):
            chars_ldev = [char for char in i[1]]
            if len(chars_ldev) == 1:
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
            if len(chars_ldev) == 2:
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
            if len(chars_ldev) == 3:
                chars_ldev.insert(0, "0")
            chars_ldev.insert(2, ":")
            text_ldev = ''.join(chars_ldev)
            horcm_ldev.append("discover_remote" + '\t' + "discover_remote_" + i[1] + "_0" + '\t' + i[
                0] + '\t' + text_ldev + '\t' + "0")
            horcm_ldev.append("discover_remote" + '\t' + "discover_remote_" + i[1] + "_h1" + '\t' + i[
                0] + '\t' + text_ldev + '\t' + "h1")
            horcm_ldev.append("discover_remote" + '\t' + "discover_remote_" + i[1] + "_h2" + '\t' + i[
                0] + '\t' + text_ldev + '\t' + "h2")
            horcm_ldev.append("discover_remote" + '\t' + "discover_remote_" + i[1] + "_h3" + '\t' + i[
                0] + '\t' + text_ldev + '\t' + "h3")
        if re.search(r'QS', i[7]) or re.search(r'MRCF', i[7]):
            chars_ldev = [char for char in i[1]]
            if len(chars_ldev) == 1:
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
            if len(chars_ldev) == 2:
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
            if len(chars_ldev) == 3:
                chars_ldev.insert(0, "0")
            chars_ldev.insert(2, ":")
            text_ldev = ''.join(chars_ldev)
            horcm_ldev.append(
                "discover_local" + '\t' + "discover_local_" + i[1] + "_0" + '\t' + i[0] + '\t' + text_ldev + '\t' + "0")
            horcm_ldev.append(
                "discover_local" + '\t' + "discover_local_" + i[1] + "_1" + '\t' + i[0] + '\t' + text_ldev + '\t' + "1")
            horcm_ldev.append(
                "discover_local" + '\t' + "discover_local_" + i[1] + "_2" + '\t' + i[0] + '\t' + text_ldev + '\t' + "2")
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return horcm_ldev


def add_horcm_ldev_data_to_horcm(horcm_instance, path, os_type):
    logger.info("Function execution started")
    start_time = time.time()
    local = False
    remote = False
    f = []
    horcm_ldev_data = output_horcm_text_data(horcm_instance)
    shutdown_horcm_instance(horcm_instance, get_horcm_path(os_type), os_type)
    horcm_file_full_path = path + "horcm" + horcm_instance + ".conf"
    with open(horcm_file_full_path, 'a') as horcm_file:
        horcm_file.write('\n' + "HORCM_LDEV" + '\n')
        horcm_file.write(
            "# dev_group" + '\t' + "dev_name" + '\t' + "Serial#" + '\t' + "CU:LDEV(LDEV#)" + '\t' + "MU#" + '\n')
        for mu in horcm_ldev_data:
            horcm_file.write(mu + '\n')
            if re.search(r'local', mu):
                local = True
            if re.search(r'remote', mu):
                remote = True
        horcm_file.write('\n' + "HORCM_INSTP" + '\n')
        if remote:
            horcm_file.write("discover_remote" + '\t' + "localhost" + '\t' + "44667" + '\n')
        if local:
            horcm_file.write("discover_local" + '\t' + "localhost" + '\t' + "44667" + '\n')
    start_horcm_instance(horcm_instance, get_horcm_path(os_type), os_type)
    with open(horcm_file_full_path, 'r') as horcm_file:
        horcm_data = horcm_file.read()
    horcm_data = horcm_data.splitlines()
    for l in horcm_data:
        l = l.split()
        f.append(l)
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return f

def discover_replication_remote(horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    array_of_mus = []
    try:
        pairdisplay_fxe = subprocess.check_output(
            ["pairdisplay", "-g", "discover_remote", "-fxe", "-CLI", "-l", "-IH" + horcm_instance])
        pairdisplay_fxc = subprocess.check_output(
            ["pairdisplay", "-g", "discover_remote", "-fxc", "-CLI", "-l", "-IH" + horcm_instance])
        pairdisplay_fxe = pairdisplay_fxe.decode().splitlines()
        for i, line in enumerate(pairdisplay_fxe):
            mu = line.split()
            array_of_mus.append(mu)
        pairdisplay_fxc = pairdisplay_fxc.decode().splitlines()
        for i, line in enumerate(pairdisplay_fxc):
            mu = line.split()
            for obj in mu:
                array_of_mus[i].append(obj)
    except:
        logger.error("pairdisplay did not work")
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return array_of_mus


def get_luns_of_a_host_grp_by_name(port, host_grp_name, horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    dict_of_luns = {}
    luns = []
    get_luns_err = False
    try:
        luns = subprocess.check_output(
            ["raidcom", "get", "lun", "-port", port, host_grp_name, "-fx", "-key", "opt", "-I" + horcm_instance])
    except:
        logger.error("raidcom get lun did not work")
        get_luns_err = True
    if not get_luns_err:
        luns = luns.splitlines()
        for lun in luns:
            lun = lun.decode()
            if not "HMO_BITs" in lun:
                lun = lun.split()
                # dict_of_luns["0x" + lun[5]] = lun[3]
                value = []
                # LDEV ID
                value.append(lun[5])
                # LUN ID
                value.append(lun[3])
                # Reserve status
                value.append(lun[8])
                dict_of_luns[lun[5]] = value
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return dict_of_luns



def get_luns_of_all_host_groups(horcm_instance):
    logger.info("Function execution started")
    start_time = time.time()
    luns = []
    columns = []
    array_of_luns = []
    array_of_host_grps = []
    host_grp_array_of_arrays = create_host_grp_array_of_arrays(horcm_instance)
    for host_grp in host_grp_array_of_arrays:
        if not re.search("GROUP_NAME", host_grp[3]):
            luns = get_luns_of_a_host_grp_by_name(host_grp[0], host_grp[3], horcm_instance)
            for l in luns:
                array_of_luns.append(
                    [host_grp[0], host_grp[1], host_grp[2], host_grp[3], host_grp[4], host_grp[5], host_grp[6],
                     host_grp[7], host_grp[8], l, luns[l][1], luns[l][2]])
        else:
            columns = host_grp
            columns.append("LDEV_ID")
            columns.append("LUN_ID")
            columns.append("Reserve_status")
    array_of_luns.insert(0, columns)
    end_time = time.time()
    execution_time = end_time - start_time
    logger.info(f"The function took {execution_time} seconds to execute.")
    return array_of_luns

def enrich_discover_replication_remote_with_rep_type(discover_replication_remote_list_of_lists):
    for i, pair_line in enumerate(discover_replication_remote_list_of_lists):
        if "P-VOL" in pair_line[8]:
            if "NEVER" in pair_line[10]:
                if "-" not in pair_line[20]:
                    discover_replication_remote_list_of_lists[i].append("GAD")
                else:
                    discover_replication_remote_list_of_lists[i].append("TC")
            if "ASYNC" in pair_line[10]:
                for x in discover_replication_remote_list_of_lists:
                    if pair_line[7] == x[7] and x[10] == "NEVER" and x[8]=="P-VOL":
                        discover_replication_remote_list_of_lists[i].append("HUR")
                    if pair_line[7] == x[7] and x[10] == "NEVER" and x[8] == "S-VOL":
                        discover_replication_remote_list_of_lists[i].append("HURD")
    return discover_replication_remote_list_of_lists

def group_discover_replication_remote_by_ctg_id(pairdisplay_list_of_lists_with_rep_type):
    replication_remote_grouped_by_ctg = {}
    for replication_remote_sub_list in pairdisplay_list_of_lists_with_rep_type[1:]:
        if "P-VOL" in replication_remote_sub_list[8]:
            # print(replication_remote_sub_list)
            key = replication_remote_sub_list[14]  ## this is the ctg id decimal value
            if key not in replication_remote_grouped_by_ctg:
                replication_remote_grouped_by_ctg[key] = []
            replication_remote_grouped_by_ctg[key].append(replication_remote_sub_list)
    return replication_remote_grouped_by_ctg

def get_host_grp_names_of_all_ctgs(replication_remote_grouped_by_ctg, horcm_instance):
    all_luns = get_luns_of_all_host_groups(horcm_instance)
    host_grp_name_of_each_ctg = {}
    for key in replication_remote_grouped_by_ctg:
        list_of_all_hsds_in_ctg = []
        for line in replication_remote_grouped_by_ctg[key]:
            ldev_id = line[7]
            for lun_line in all_luns:
                if ldev_id == lun_line[9]:
                    # print(ldev_id + " " + lun_line[9])
                    # print(lun_line)
                    if "@" in lun_line[3]:
                        hsd = lun_line[3].split("@")
                        hsdstr = ''.join(hsd[:-1])
                        # print(hsdstr)
                    else:
                        hsdstr = lun_line[3]
                    if not "BACKUP-APPL" in hsdstr:
                        list_of_all_hsds_in_ctg.append(hsdstr)
        uniq_list_of_all_hsds_in_ctg = list(set(list_of_all_hsds_in_ctg))
        uniq_list_of_all_hsds_in_ctg_str = ''.join(uniq_list_of_all_hsds_in_ctg)
        host_grp_name_of_each_ctg[key] = uniq_list_of_all_hsds_in_ctg
        # print(uniq_list_of_all_hsds_in_ctg)
        # print(key)
        list_of_all_hsds_in_ctg = []
    return host_grp_name_of_each_ctg





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
# print(main_dict)
# print('\n')

#Add discover to HORCM files and create dict_of_replication_remote_list_of_list for which thy key is the serial number and the value is a list of list, each sub list is a "pairdisplay" line.
dict_of_replication_remote_list_of_list = {}
dict_of_pairdisplay_by_sn_and_ctg = {}
dict_of_host_grp_name_of_each_ctg_by_sn = {}

dict_of_horcm_ldev_data_by_sn = {}
dict_of_horcm_inst_data_by_sn = {}

for sn in main_dict:
    print(sn)
    print(main_dict[sn])
    add_horcm_ldev_data_to_horcm(main_dict[sn]['horcm_instance'], get_horcm_path(os_type), os_type)
    dict_of_replication_remote_list_of_list[sn] = []
    dict_of_replication_remote_list_of_list[sn] = discover_replication_remote(main_dict[sn]['horcm_instance'])
    enrich_discover_replication_remote_with_rep_type(dict_of_replication_remote_list_of_list[sn])
    dict_of_pairdisplay_by_sn_and_ctg[sn] = {}
    dict_of_pairdisplay_by_sn_and_ctg[sn] = group_discover_replication_remote_by_ctg_id(dict_of_replication_remote_list_of_list[sn])
    dict_of_host_grp_name_of_each_ctg_by_sn[sn] = get_host_grp_names_of_all_ctgs(dict_of_pairdisplay_by_sn_and_ctg[sn], main_dict[sn]['horcm_instance'])
    if sn not in dict_of_horcm_ldev_data_by_sn:
        dict_of_horcm_ldev_data_by_sn[sn] = []
        dict_of_horcm_ldev_data_by_sn[sn].append('\n' + "HORCM_LDEV" + '\n')
    if sn not in dict_of_horcm_inst_data_by_sn:
        dict_of_horcm_inst_data_by_sn[sn] = []
        dict_of_horcm_inst_data_by_sn[sn].append('\n' + "HORCM_INST" + '\n')

for sn in main_dict:
    for ctg in dict_of_pairdisplay_by_sn_and_ctg[sn]:
        dict_of_horcm_ldev_data_by_sn[sn].append("#CTG: " + ctg)
        for line in dict_of_pairdisplay_by_sn_and_ctg[sn][ctg]:
            mu = line[1].split("_")[-1]
            ldev_id = line[7]
            local_serial = line[6]
            remote_serial = line[11]
            replication_type = line[39]
            host_grp_name_of_each_ctg_str = '_'.join(dict_of_host_grp_name_of_each_ctg_by_sn[sn][ctg])
            chars_ldev = [char for char in ldev_id]
            if len(chars_ldev) == 1:
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
            if len(chars_ldev) == 2:
                chars_ldev.insert(0, "0")
                chars_ldev.insert(0, "0")
            if len(chars_ldev) == 3:
                chars_ldev.insert(0, "0")
            chars_ldev.insert(2, ":")
            text_ldev = ''.join(chars_ldev)
            horcm_ldev_data_line_local = "CTG_" + ctg + "_" + host_grp_name_of_each_ctg_str[:22] + " " + "ldev_" + ldev_id + "_" + mu + "_" + replication_type + " " + local_serial + " " + text_ldev + " " + mu + " # replicated to: " + remote_serial
            horcm_ldev_data_line_remote = "CTG_" + ctg + "_" + host_grp_name_of_each_ctg_str[:22] + " " + "ldev_" + ldev_id + "_" + mu + "_" + replication_type + " " + remote_serial + " " + text_ldev + " " + mu + " # replicated from: " + local_serial
            dict_of_horcm_ldev_data_by_sn[sn].append(horcm_ldev_data_line_local)
            dict_of_horcm_ldev_data_by_sn[remote_serial].append(horcm_ldev_data_line_remote)

for sn in main_dict:
    horcm_instp_data_tmp = []
    uniq_horcm_grp = []
    for one_horcm_ldev_data_line in dict_of_horcm_ldev_data_by_sn[sn][1:]:
        one_horcm_ldev_data_line_array = one_horcm_ldev_data_line.split()
        if "#" not in one_horcm_ldev_data_line_array[0]:
            horcm_instp_data_tmp.append(one_horcm_ldev_data_line_array[0])
    uniq_horcm_grp = list(set(horcm_instp_data_tmp))
    for uniq_horcm_grp_item in uniq_horcm_grp:
        for pair_dsp_line in dict_of_horcm_ldev_data_by_sn[sn][1:]:
            pair_dsp_line = pair_dsp_line.split()
            pair_serial_remote = pair_dsp_line[-1]
            if uniq_horcm_grp_item in pair_dsp_line:
                remote_udp = main_dict[pair_serial_remote]['horcm_udp_port']
        dict_of_horcm_inst_data_by_sn[sn].append(uniq_horcm_grp_item + "       localhost       " + remote_udp)




#re-init main dict and cleanup horcm files, create fresh horcm files:
main_dict = init_main_dict(connectionstrings_list, usernames_list, passwords_list, instances_list, numbersofudpports_list)
# print(main_dict)
# print('\n')


for sn in dict_of_pairdisplay_by_sn_and_ctg:
    print(sn)
    # print(dict_of_host_grp_name_of_each_ctg_by_sn[sn])
    # # print(dict_of_pairdisplay_by_sn_and_ctg[sn])
    # for ctg in dict_of_pairdisplay_by_sn_and_ctg[sn]:
    #     print(ctg)
    #     # print(dict_of_pairdisplay_by_sn_and_ctg[sn][ctg])
    #     for pairdisplay_line in dict_of_pairdisplay_by_sn_and_ctg[sn][ctg]:
    #         print(pairdisplay_line)
    for line in dict_of_horcm_ldev_data_by_sn[sn]:
        print(line)
    for line in dict_of_horcm_inst_data_by_sn[sn]:
        print(line)

#Write horcm ldev and horcm inst data to horcm files:
for sn in main_dict:
    shutdown_horcm_instance(main_dict[sn]['horcm_instance'], horcm_path, os_type)
    horcm_file_full_path = horcm_path + "horcm" + main_dict[sn]['horcm_instance'] + ".conf"
    with open(horcm_file_full_path, 'a') as horcm_file:
        for one_horcm_ldev_data_line in dict_of_horcm_ldev_data_by_sn[sn]:
            horcm_file.writelines(one_horcm_ldev_data_line + '\n')
        for one_horcm_inst_data_line in dict_of_horcm_inst_data_by_sn[sn]:
            horcm_file.writelines(one_horcm_inst_data_line + '\n')


# 560311
# {'22': ['alex_test_gad'], '0': ['alex_test_gad'], '1': ['first_3dc_cluster'], '7': ['first_3dc_cluster']}
# 22
# ['discover_remote', 'discover_remote_c8_0', 'L', 'CL7-A-10', '1', '0', '560311', 'c8', 'P-VOL', 'PAIR', 'NEVER', '540491', 'c8', '-', '22', '0', '-', '-', '-', '-', 'L/M', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_c8_0', 'L', 'CL7-A-10', '1', '0', '560311', 'c8', 'P-VOL', 'PAIR', 'NEVER', '100', 'c8', '-', 'GAD']
# 0
# ['discover_remote', 'discover_remote_c8_h1', 'L', 'CL7-A-10', '1', '0', '560311', 'c8', 'P-VOL', 'PAIR', 'ASYNC', '533610', 'c8', '-', '0', '5', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_c8_h1', 'L', 'CL7-A-10', '1', '0', '560311', 'c8', 'P-VOL', 'PAIR', 'ASYNC', '0', 'c8', '-', 'HUR']
# 1
# ['discover_remote', 'discover_remote_c9_h1', 'L', 'CL1-A-1', '1', '0', '560311', 'c9', 'P-VOL', 'PAIR', 'NEVER', '540491', 'c9', '-', '1', '0', '-', '-', '-', '-', 'L/M', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_c9_h1', 'L', 'CL1-A-1', '1', '0', '560311', 'c9', 'P-VOL', 'PAIR', 'NEVER', '100', 'c9', '-', 'GAD']
# ['discover_remote', 'discover_remote_ca_h1', 'L', 'CL1-A-1', '1', '1', '560311', 'ca', 'P-VOL', 'PAIR', 'NEVER', '540491', 'ca', '-', '1', '0', '-', '-', '-', '-', 'L/M', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_ca_h1', 'L', 'CL1-A-1', '1', '1', '560311', 'ca', 'P-VOL', 'PAIR', 'NEVER', '100', 'ca', '-', 'GAD']
# ['discover_remote', 'discover_remote_cb_h1', 'L', 'CL1-A-1', '1', '2', '560311', 'cb', 'P-VOL', 'PAIR', 'NEVER', '540491', 'cb', '-', '1', '0', '-', '-', '-', '-', 'L/M', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_cb_h1', 'L', 'CL1-A-1', '1', '2', '560311', 'cb', 'P-VOL', 'PAIR', 'NEVER', '100', 'cb', '-', 'GAD']
# 7
# ['discover_remote', 'discover_remote_c9_h2', 'L', 'CL1-A-1', '1', '0', '560311', 'c9', 'P-VOL', 'PAIR', 'ASYNC', '533610', 'c9', '-', '7', '6', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_c9_h2', 'L', 'CL1-A-1', '1', '0', '560311', 'c9', 'P-VOL', 'PAIR', 'ASYNC', '0', 'c9', '-', 'HUR']
# ['discover_remote', 'discover_remote_ca_h2', 'L', 'CL1-A-1', '1', '1', '560311', 'ca', 'P-VOL', 'PAIR', 'ASYNC', '533610', 'ca', '-', '7', '6', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_ca_h2', 'L', 'CL1-A-1', '1', '1', '560311', 'ca', 'P-VOL', 'PAIR', 'ASYNC', '0', 'ca', '-', 'HUR']
# ['discover_remote', 'discover_remote_cb_h2', 'L', 'CL1-A-1', '1', '2', '560311', 'cb', 'P-VOL', 'PAIR', 'ASYNC', '533610', 'cb', '-', '7', '6', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_cb_h2', 'L', 'CL1-A-1', '1', '2', '560311', 'cb', 'P-VOL', 'PAIR', 'ASYNC', '0', 'cb', '-', 'HUR']
# 540491
# {'0': ['alex_test_gad'], '6': ['first_3dc_cluster']}
# 0
# ['discover_remote', 'discover_remote_c8_h2', 'L', 'CL7-A-10', '1', '0', '540491', 'c8', 'P-VOL', 'PSUE', 'ASYNC', '533610', 'c8', '-', '0', '5', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_c8_h2', 'L', 'CL7-A-10', '1', '0', '540491', 'c8', 'P-VOL', 'PSUE', 'ASYNC', '0', 'c8', '-', 'HURD']
# 6
# ['discover_remote', 'discover_remote_c9_h3', 'L', 'CL1-A-1', '1', '0', '540491', 'c9', 'P-VOL', 'PSUE', 'ASYNC', '533610', 'c9', '-', '6', '6', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_c9_h3', 'L', 'CL1-A-1', '1', '0', '540491', 'c9', 'P-VOL', 'PSUE', 'ASYNC', '0', 'c9', '-', 'HURD']
# ['discover_remote', 'discover_remote_ca_h3', 'L', 'CL1-A-1', '1', '1', '540491', 'ca', 'P-VOL', 'PSUE', 'ASYNC', '533610', 'ca', '-', '6', '6', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_ca_h3', 'L', 'CL1-A-1', '1', '1', '540491', 'ca', 'P-VOL', 'PSUE', 'ASYNC', '0', 'ca', '-', 'HURD']
# ['discover_remote', 'discover_remote_cb_h3', 'L', 'CL1-A-1', '1', '2', '540491', 'cb', 'P-VOL', 'PSUE', 'ASYNC', '533610', 'cb', '-', '6', '6', '-', '-', '-', '-', '-/-', '-', '-', 'N', '-', 'discover_remote', 'discover_remote_cb_h3', 'L', 'CL1-A-1', '1', '2', '540491', 'cb', 'P-VOL', 'PSUE', 'ASYNC', '0', 'cb', '-', 'HURD']
# 533610
# {}