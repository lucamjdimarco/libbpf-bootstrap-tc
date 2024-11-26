from typing import Coroutine
import settings
import subprocess
import os
import json
from hex_types import u64, u32, u16, u8, s8, to_hex
from settings import BPF_FS_PATH


import redis
import time
import os
import requests
import sys

# REDIS #
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

# INFLUXDB #
URL_IPV4 = "http://influxdb:8086/query?db=tc_db"
URL_IPV6 = "http://10.89.0.30:8086/query?db=tc_db"

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
        # Converti key e value in formato little-endian
        key_bytes = struct.pack("<I", key)  # 32-bit unsigned integer
        value_bytes = struct.pack("<Q", value)  # 64-bit unsigned integer

        key_hex = " ".join(f"0x{b:02x}" for b in key_bytes)
        value_hex = " ".join(f"0x{b:02x}" for b in value_bytes)

        # Costruisci il comando bpftool
        cmd = f"bpftool map update pinned {map_path} key {key_hex} value {value_hex}"
        print(f"Exec: {cmd}")
        ret = os.system(cmd)
        if ret != 0:
            raise Exception(f"Failed to update map at {map_path} with key {key} and value {value}")
    else:
        raise Exception(
            "bpftool_map_update: Instruction not implemented (invalid map_reference_type).")

    print(f"Exec: {cmd}")
    ret = os.system(cmd)

    if ret != 0:
        raise Exception(f"Map update {map_reference} failed.")

    # unittest
    return True


def cal_map_update(map_reference, key, value):
    key_list = to_hex(key)
    value_list = to_hex(value)
    #print (key_list)
    #print (value_list)
    bpftool_map_update(map_reference, key_list, value_list,
                       map_reference_type="pinned", value_type="hex")


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
    import struct
    key_bytes = struct.pack("<I", key)
    key_data_string = (" ".join(hex(n)
                                for n in key_bytes))

    if map_reference_type == "pinned":
        cmd = f"bpftool map lookup --json pinned {map_reference} key {key_data_string}"
    else:
        raise Exception(
            "bpftool_map_lookup: Instruction not implemented (invalid map_reference_type).")

    print(f"Exec: {cmd}")
    result = subprocess.run(cmd.split(), stdout=subprocess.PIPE)

    if result.returncode != 0:
        raise Exception(f"Map lookup {map_reference} failed.")
    else:
        return result.stdout.decode("utf-8")


def bpftool_map_create(map_name, map_path, key_size, value_size, max_entries, type="hash"):
    '''Call bpftool map create and return the result
    '''
    # bpftool map create <map_path> type <type> key <key_size> value <value_size> entries <max_entries> name <map_name>
    cmd = f"bpftool map create {map_path} type {type} key {key_size} value {value_size} entries {max_entries} name {map_name}"

    print(f"Exec: {cmd}")
    result = subprocess.run(cmd.split(), stdout=subprocess.PIPE)

    if result.returncode != 0:
        raise Exception(f"Map create {map_path} failed.")
    else:
        return result.stdout.decode("utf-8")

def get_ifindex(interface_name):
    """
    Get the ifindex for a given interface name.
    """
    try:
        return int(subprocess.check_output(["cat", f"/sys/class/net/{interface_name}/ifindex"]).strip())
    except Exception as e:
        raise Exception(f"Failed to get ifindex for interface {interface_name}: {e}")
    
def main():
    
    # if len(sys.argv) < 2:
    #     print("Usage: python3 EFE-controller.py <interface>")
    #     sys.exit(1)

    
    # interface = sys.argv[1]
    # print(f"Received interface: {interface}")

    
    # query = f"""
    # SELECT * 
    # FROM "tc_db"."autogen"."rate" 
    # WHERE "id" =~ /^{machine_id}:{interface}:/
    # """

    # params = {
    #     "db": "tc_db",
    #     "q": query
    # }

    # try:
    #     mount_bpf(BPF_FS_PATH)
    #     print(f"BPF filesystem montato su {BPF_FS_PATH}")
    # except OSError as e:
    #     print(f"Errore durante il montaggio del filesystem BPF: {e}")
    #     exit(1)

    # try:
    #     response = requests.get(URL_IPV6, params=params)
    #     response.raise_for_status()
    #     data = response.json()

    #     #print(json.dumps(data, indent=4))
        
        
    #     max_flowid = None
        
    #     # Verifica se ci sono risultati
    #     if "series" in data["results"][0]:
    #         series = data["results"][0]["series"]
    #         for value in series[0]["values"]:
    #             id_value = value[1] 
                
    #             #print(f"Valore grezzo id_value: {id_value}")
                
    #             if isinstance(id_value, str) and ":" in id_value:
    #                 try:
    #                     flowid = int(id_value.split(":")[-1])
    #                     #print(f"Flow ID estratto: {flowid}")
                        
    #                     if max_flowid is None or flowid > max_flowid:
    #                         max_flowid = flowid
    #                 except ValueError:
    #                     print(f"Errore: Impossibile convertire {id_value} in un intero.")
    #             else:
    #                 print(f"Formato non valido per id_value: {id_value}")
            
    #         if max_flowid is not None:
    #             print(f"Flow ID massimo trovato: {max_flowid}")
    #         else:
    #             print("Nessun flowid valido trovato.")
    #     else:
            
    #         print("Nessun risultato trovato nella query.")
    #         # Se non ci sono risultati, aggiorna la mappa flowpy_map
    #         bpftool_map_update("/sys/fs/bpf/flowpy_map", 0, 0)  # Mappa eBPF a chiave 0 e valore 0
    # except requests.exceptions.RequestException as e:
    #     print(f"Errore nella richiesta: {e}")
    # except ValueError as e:
    #     print(f"Errore nella conversione del flowid: {e}")

    #Debug stampa ogni 2 secondi una stringa
    
    

    if len(os.sys.argv) != 2:
        print("Usage: python3 script.py <interface>")
        exit(1)

    interface_name = os.sys.argv[1]
    
    try:
        mount_bpf(BPF_FS_PATH)
        print(f"BPF filesystem mounted on {BPF_FS_PATH}")
    except OSError as e:
        print(f"Error mounting BPF filesystem: {e}")
        exit(1)

    try:
        ifindex = get_ifindex(interface_name)
        print(f"Interface {interface_name} has ifindex {ifindex}")

        # Check if ifindex exists in the map
        map_result = bpftool_map_lookup(FLOWPY_MAP_PATH, ifindex)
        if map_result:
            print(f"Value for ifindex {ifindex} already exists in map: {map_result}")
        else:
            print(f"No value found for ifindex {ifindex}. Initializing with 0.")
            bpftool_map_update(FLOWPY_MAP_PATH, ifindex, 0)

        # Periodically print the value from the map
        while True:
            try:
                map_result = bpftool_map_lookup(FLOWPY_MAP_PATH, ifindex)
                if map_result:
                    print(f"Current value for ifindex {ifindex}: {map_result}")
                else:
                    print(f"No value found for ifindex {ifindex}.")
                time.sleep(2)
            except KeyboardInterrupt:
                print("Process interrupted.")
                break

    except Exception as e:
        print(f"Error: {e}")
        exit(1)





if __name__ == "__main__":
    main()