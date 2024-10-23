import redis
import os
from bcc import BPF
import time

#Connessione al server di Redis 
r = redis.Redis(host='redis', port=6379, db=0)

#Recuperare l'ID della macchina come machine-id --> /etc/machine-id
machine_id = os.popen("cat /etc/machine-id").read().strip()

last_flow_id = r.get(machine_id)

if last_flow_id is None:
    last_flow_id = 0 

#Gestione di un nuovo flusso
def process_new_flow(flow_id):
    
    b = BPF(src_file="tc.bpf.c")
    flow_map = b.get_table("flowpy_map")
    flow_map[b["flow_key"]] = flow_id

    #Aggiornamento del flow ID
    r.set(machine_id, flow_id)


