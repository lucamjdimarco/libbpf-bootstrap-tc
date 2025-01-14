import redis
import sys
import os
import argparse

r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()


def set_friendlyname(hfn):
    global friendlyname
    try:
        # Check if a value exists for the machine_id
        existing_value = r.get(machine_id)
        if existing_value:
        
            friendlyname = existing_value.decode('utf-8')
            print(f"Friendlyname already exists for Machine ID '{machine_id}': {friendlyname}")
        else:
    
            friendlyname = hfn
            r.set(machine_id, friendlyname)
            print(f"Friendlyname '{friendlyname}' saved for Machine ID '{machine_id}'!")

    except Exception as e:
        print(f"An error occurred: {e}")



def check_hfn:
