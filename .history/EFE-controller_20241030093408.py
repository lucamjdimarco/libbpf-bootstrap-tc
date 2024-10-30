from bcc import BPF
import redis
import time
import os

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

b = BPF(src_file="tc.bpf.c")

# Attiva il programma eBPF
b.attach_kprobe(event='clone', fn_name='track_clone')

# Se non esiste la chiave machine_id in Redis, la inizializza con valore 0
if r.get(machine_id) is None:
    r.set(machine_id, 0)

# Funzione per recuperare l'ultimo flow_id dalla mappa eBPF
def get_current_flow_id():
    try:
        value = b.get_map("flowpy_map").get(0)  # Accede alla chiave fissa 0 nella mappa
        return value
    except KeyError:
        # Se la chiave non esiste, restituisce None
        return None

# Loop infinito per aggiornare Redis con il flow_id corrente
while True:
    current_flow_id = get_current_flow_id()
    
    if current_flow_id is not None:
        print(f"Flow ID corrente: {current_flow_id}")
        r.set(machine_id, current_flow_id)
    
    time.sleep(10)
