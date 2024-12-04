from typing import Coroutine
import settings
import subprocess
import os
import json
from hex_types import u64, u32, u16, u8, s8, to_hex
from settings import BPF_FS_PATH
from enum import Enum

import socket
import struct


import redis
import time
import os
import requests
import sys
import struct

class MapType(Enum):
    map_ipv4 = 1
    map_ipv6 = 2
    map_only_addr_ipv4 = 3
    map_only_addr_ipv6 = 4
    map_only_dest_ipv4 = 5
    map_only_dest_ipv6 = 6


# REDIS #
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

DB_NAME = "tc_db"

protocol = sys.argv[2]
type_of_classifier = sys.argv[3]


# INFLUXDB #
INFLUXDB_URL_IPV4 = "http://influxdb:8086/query?db=tc_db"
INFLUXDB_URL_IPV6 = "http://10.89.0.30:8086/query?db=tc_db"

FLOWPY_MAP_PATH = f"{BPF_FS_PATH}/flowpy_map"


def mount_bpf(mount_point):
    """
    mount -t bpf bpf /sys/fs/bpf/
    """
    # Everything that is private to the bash process that will be launch
    # mount the bpf filesystem.
    # Note: childs of the launching (parent) bash can access this instance
    # of the bpf filesystem. If you need to get access to the bpf filesystem
    # (where maps are available), you need to use nsenter with -m and -t
    # that points to the pid of the parent process (launching bash).
    cmd = f"grep -qs '{mount_point} ' /proc/mounts || mount -t bpf bpf {mount_point}"
    print(f"Exec: {cmd}")
    ret = os.system(cmd)
    if ret:
        raise OSError(f"Can not mount BPF fs on {mount_point}")




# bpftool map update MAP [key DATA] [value VALUE] [UPDATE_FLAGS]
# MAP := {id MAP_ID | pinned FILE | name MAP_NAME}
# DATA := {[hex] BYTES}
# VALUE := {DATA | MAP | PROG}
# UPDATE_FLAGS := {any | exist | noexist}
# bpftool map update pinned /sys/fs/bpf/maps/init/gen_jmp_table 	\
#		key	hex 0b 00 00 00					\
#		value	pinned /sys/fs/bpf/progs/net/hvxdp_allow_any


# bpftool map update id <id> key <key> value <new_value>
# bpftool map update pinned <path> key <key> value <new_value>
def bpftool_map_update(map_reference, key, value, map_reference_type="pinned", value_type="pinned"):
    """Update a eBPF map

    :param map_reference: ID of the map or sys/fs path if reference refers to a pinned map
    :param key: key to update (passed as list of hex)
    :param value: value to be written
    :param map_reference_type: id or pinned, defaults to "pinned"
    :param value_type: pinned or hex
    """
    

    if map_reference_type == "pinned":
        # converto key e value in formato little-endian
        key_bytes = struct.pack("<I", key)  # 32-bit unsigned integer
        value_bytes = struct.pack("<Q", value)  # 64-bit unsigned integer

        key_hex = " ".join(f"0x{b:02x}" for b in key_bytes)
        value_hex = " ".join(f"0x{b:02x}" for b in value_bytes)

        cmd = f"bpftool map update pinned {map_reference} key {key_hex} value {value_hex}"
        print(f"Exec: {cmd}")
        ret = os.system(cmd)
        if ret != 0:
            raise Exception(f"Failed to update map at {map_reference} with key {key_hex} and value {value_hex}")
    else:
        raise Exception(
            "bpftool_map_update: Instruction not implemented (invalid map_reference_type).")

    # unittest
    return True



def bpftool_map_dump(map_reference, map_reference_type="pinned"):
    """Call bpftool map dump and return the result
    """
    # bpftool map dump pinned /sys/fs/bpf/maps/system/hvm_chain_map

    if map_reference_type == "pinned":

        cmd = f"bpftool map dump pinned {map_reference}"
    else:
        raise Exception(
            "bpftool_map_dump: Instruction not implemented (invalid map_reference_type).")

    print(f"Exec: {cmd}")
    result = subprocess.run(cmd.split(), stdout=subprocess.PIPE)

    if result.returncode != 0:
        raise Exception(f"Map dump {map_reference} failed.")
    else:
        return result.stdout.decode("utf-8")


def bpftool_map_lookup(map_reference, key, map_reference_type="pinned"):
    """Call bpftool map lookup and return the result
    """
    # bpftool map lookup --json pinned /sys/fs/bpf/maps/system/hvm_chain_map key 0x40 0x00 0x00 0x00
    # formato little-endian
    key_bytes = struct.pack("<I", key)
    key_data_string = " ".join(hex(n) for n in key_bytes)

    if map_reference_type == "pinned":
        cmd = f"bpftool map lookup --json pinned {map_reference} key {key_data_string}"
    else:
        raise Exception("bpftool_map_lookup: Invalid map_reference_type.")

    print(f"Exec: {cmd}")
    result = subprocess.run(cmd.split(), stdout=subprocess.PIPE, text=True)

    if result.returncode != 0:
        print(f"Map lookup failed for {map_reference} with key {key}.")
        return None

    try:
        result_json = json.loads(result.stdout)
        return int(result_json.get("value", "0x0"), 16) 
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Error parsing lookup result: {e}")
        return None



def get_ifindex(interface_name):
    """
    Get the ifindex for a given interface name.
    """
    try:
        return int(subprocess.check_output(["cat", f"/sys/class/net/{interface_name}/ifindex"]).strip())
    except Exception as e:
        raise Exception(f"Failed to get ifindex for interface {interface_name}: {e}")
    
def query_influxdb(machine_id, interface):
    query = f"""
    SELECT *
    FROM "{DB_NAME}"."autogen"."rate"
    WHERE "machine_id"='{machine_id}' AND "interface"='{interface}'
    """
    params = {"q": query, "db": DB_NAME}

    try:
        # GET request to InfluxDB with the query
        if(protocol == "ipv4"):
            response = requests.get(INFLUXDB_URL_IPV6, params=params)
        else:
            response = requests.get(INFLUXDB_URL_IPV4, params=params)
        response.raise_for_status() 
        data = response.json()

        # Extract series from the query result
        series = data["results"][0].get("series", [])
        if series:
            # Extract all `flowid` values from the result
            flowids = [
                int(row[1])  # `flowid` is the second column
                for row in series[0]["values"]
                if row[1].isdigit() 
            ]
            if flowids:
                # Get the maximum `flowid`
                max_flowid = max(flowids)
                print(f"Max flowid found: {max_flowid}")
                return max_flowid
            else:
                print("No valid flowid found.")
        else:
            print("No series found in query result.")
    except Exception as e:
        print(f"Error querying InfluxDB: {e}")
    return None
    
def dump_map_contents(map_path):
    try:
        map_dump = bpftool_map_dump(map_path)
        return json.loads(map_dump)  
    except Exception as e:
        print(f"Error dumping map contents for {map_path}: {e}")
        return None

def parse_map_dump_to_json(dump_data, classifier):
    """
    Parse and format map dump data from bpftool based on the classifier and return as a JSON structure.
    """
    try:
        # Check if dump_data is already a Python list
        if isinstance(dump_data, list):
            map_entries = dump_data
        else:
            map_entries = json.loads(dump_data)

        formatted_data = []  # List to hold formatted entries

        for entry in map_entries:
            key = entry.get("key", {})
            value = entry.get("value", {})

            if classifier == 1:  # IPv4 quintuple
                src_ip = socket.inet_ntoa(struct.pack('<I', key.get("src_ip", 0)))
                dst_ip = socket.inet_ntoa(struct.pack('<I', key.get("dst_ip", 0)))
                src_port = key.get("src_port", 0)
                dst_port = key.get("dst_port", 0)
                protocol = key.get("protocol", 0)
                flow_id = value.get("flow_id", 0)

                formatted_data.append({
                    "flow_id": flow_id,
                    "source": {"ip": src_ip, "port": src_port},
                    "destination": {"ip": dst_ip, "port": dst_port},
                    "protocol": protocol
                })

            elif classifier == 2:  # IPv6 quintuple
                src_ip = socket.inet_ntop(socket.AF_INET6, bytes(key.get("src_ip", [0] * 16)))
                dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(key.get("dst_ip", [0] * 16)))
                src_port = key.get("src_port", 0)
                dst_port = key.get("dst_port", 0)
                protocol = key.get("protocol", 0)
                flow_id = value.get("flow_id", 0)

                formatted_data.append({
                    "flow_id": flow_id,
                    "source": {"ip": src_ip, "port": src_port},
                    "destination": {"ip": dst_ip, "port": dst_port},
                    "protocol": protocol
                })

            elif classifier == 3:  # Only IPv4 addresses
                src_ip = socket.inet_ntoa(struct.pack('<I', key.get("src_ip", 0)))
                dst_ip = socket.inet_ntoa(struct.pack('<I', key.get("dst_ip", 0)))
                flow_id = value.get("flow_id", 0)

                formatted_data.append({
                    "flow_id": flow_id,
                    "source": {"ip": src_ip},
                    "destination": {"ip": dst_ip}
                })

            elif classifier == 4:  # Only IPv6 addresses
                src_ip = socket.inet_ntop(socket.AF_INET6, bytes(key.get("src_ip", [0] * 16)))
                dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(key.get("dst_ip", [0] * 16)))
                flow_id = value.get("flow_id", 0)

                formatted_data.append({
                    "flow_id": flow_id,
                    "source": {"ip": src_ip},
                    "destination": {"ip": dst_ip}
                })

            elif classifier == 5:  # Only IPv4 destination address
                dst_ip = socket.inet_ntoa(struct.pack('<I', key.get("dst_ip", 0)))
                flow_id = value.get("flow_id", 0)

                formatted_data.append({
                    "flow_id": flow_id,
                    "destination": {"ip": dst_ip}
                })

            elif classifier == 6:  # Only IPv6 destination address
                dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(key.get("dst_ip", [0] * 16)))
                flow_id = value.get("flow_id", 0)

                formatted_data.append({
                    "flow_id": flow_id,
                    "destination": {"ip": dst_ip}
                })

            else:
                raise ValueError(f"Unsupported classifier type: {classifier}")

        return formatted_data

    except Exception as e:
        print(f"Error parsing map dump: {e}")
        return {"error": str(e)}
    
def write_to_redis(redis_client, key, data):
    """
    Write data to Redis, overwriting existing entries.
    """
    try:
        redis_client.set(key, json.dumps(data))
    except Exception as e:
        print(f"Error writing to Redis: {e}")
    
def get_map_path(type_of_classifier):
    try:
        classifier_enum = MapType(int(type_of_classifier))
        map_name = classifier_enum.name  
        map_path = f"{BPF_FS_PATH}/{map_name}" 
        return map_path
    except ValueError:
        print(f"Invalid type_of_classifier: {type_of_classifier}")
        return None


    
def main():
    if len(sys.argv) != 4:
        print("Usage: python3 script.py <interface> <protocol> <type_of_classifier> <friendlyname>") 
        exit(1)

    interface_name = sys.argv[1]

    try:
        mount_bpf(BPF_FS_PATH)
        print(f"BPF filesystem mounted on {BPF_FS_PATH}")
    except OSError as e:
        print(f"Error mounting BPF filesystem: {e}")
        exit(1)

    try:
        ifindex = get_ifindex(interface_name)
        print(f"Interface {interface_name} has ifindex {ifindex}")

        # Query InfluxDB for flow ID
        flow_id = query_influxdb(machine_id, interface_name)
        if flow_id is not None:
            print(f"Found flow ID {flow_id} for machine_id {machine_id} and interface {interface_name}")
        else:
            print(f"No flow ID found for machine_id {machine_id} and interface {interface_name}. Initializing to 0.")
            flow_id = 0

        # Update the map
        bpftool_map_update(FLOWPY_MAP_PATH, ifindex, flow_id)

        # Get the map path for the classifier type
        map_path = get_map_path(type_of_classifier)
        if not map_path:
            print("Failed to determine map path for the given classifier type.")
            exit(1)
        
        # Set the friendlyname in Redis
        #set_friendlyname(sys.argv[4])

        # Periodically dump and print the map contents
        while True:
            try:
                map_contents = dump_map_contents(map_path)
                
                if map_contents:
                    data_formatted = parse_map_dump_to_json(map_contents, int(type_of_classifier))
                    #print(data_formatted)  # Pretty-print the map contents

                    if "error" in data_formatted:
                        print(f"Error in parsing: {data_formatted['error']}")
                    else:
                        # Write each entry to Redis
                        for entry in data_formatted:
                            flow_id = entry["flow_id"]
                            redis_key = f"flow:{flow_id}"
                            write_to_redis(r, redis_key, entry)

                else:
                    print(f"No data found in map: {map_path}")
                time.sleep(5)
            except KeyboardInterrupt:
                print("Process interrupted.")
                break

    except Exception as e:
        print(f"Error: {e}")
        exit(1)


if __name__ == "__main__":
    main()