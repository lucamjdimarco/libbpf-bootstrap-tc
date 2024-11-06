from bcc import BPF
import redis
import time
import os
import ctypes

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

# Crea un'istanza BPF senza caricare un file sorgente
bpf_instance = BPF()

# Funzione per recuperare l'ultimo flow_id dalla mappa eBPF
def get_current_flow_id():
    try:
        flow_map = bpf_instance.get_table("flowpy_map")  # Accede alla mappa eBPF
        key = ctypes.c_uint32(0)  # Usa chiave fissa 0
        value = flow_map[key].value
        return value
    except KeyError:
        return None

# Inizializza la chiave machine_id in Redis con valore 0, se non esiste
if r.get(machine_id) is None:
    r.set(machine_id, 0)

# Loop infinito per aggiornare Redis con il flow_id corrente
while True:
    current_flow_id = get_current_flow_id()
    
    if current_flow_id is not None:
        print(f"Flow ID corrente: {current_flow_id}")
        r.set(machine_id, current_flow_id)
    
    time.sleep(10)
