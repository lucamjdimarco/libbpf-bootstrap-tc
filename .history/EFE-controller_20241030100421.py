from bcc import BPF
import redis
import time
import os

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

# Carica e attacca il programma eBPF dal file sorgente
b = BPF(src_file="src/c/tc.bpf.c")

# Attiva il programma eBPF per monitorare la syscall 'clone' e chiama la funzione definita in eBPF 'track_clone'
b.attach_kprobe(event="clone", fn_name="track_clone")

# Inizializza la chiave machine_id in Redis con valore 0, se non esiste
if r.get(machine_id) is None:
    r.set(machine_id, 0)

# Funzione per recuperare l'ultimo flow_id dalla mappa eBPF
def get_current_flow_id():
    try:
        flow_map = b.get_table("flowpy_map")  # Accede alla mappa eBPF
        value = flow_map[0].value  # Accede alla chiave fissa 0
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
