import redis
import os
from bcc import BPF

#Connessione al server di Redis 
r = redis.Redis(host='redis', port=6379, db=0)

#Recuperare l'ID della macchina come machine-id --> /etc/machine-id
machine_id = os.popen("cat /etc/machine-id").read().strip()

last_flow_id = r.get(machine_id)

if last_flow_id is None:
    last_flow_id = 0 

#Gestione di un nuovo flusso
def process_new_flow(flow_id):
    # Aggiorna la mappa eBPF con il nuovo flow ID
    b = BPF(src_file="ebpf_program.c")
    flow_map = b.get_table("flow_map")
    flow_map[b["flow_key"]] = flow_id

    # Scrivi il nuovo flow ID su Redis per renderlo persistente
    r.set(machine_id, flow_id)

# Supponiamo che venga generato un nuovo flow ID
new_flow_id = last_flow_id + 1
process_new_flow(new_flow_id)
