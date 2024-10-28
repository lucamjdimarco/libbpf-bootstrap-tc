import pyebpf
import redis
import time
import os

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

# Compila e carica il programma eBPF
with open("src/c/tc.bpf.c", "r") as f:
    bpf_code = f.read()
    
b = pyebpf.BPF(text=bpf_code)

# Ottiene la mappa eBPF
flow_map = b.get_map("flowpy_map")

# Se non esiste la chiave machine_id in Redis, la inizializza con valore 0 (primissimo flow)
if r.get(machine_id) is None:
    r.set(machine_id, 0)

# Funzione per recuperare l'ultimo flow_id dalla mappa eBPF
def get_current_flow_id():
    try:
        value = flow_map[0]  # Accede alla chiave fissa 0
        return value
    except KeyError:
        # Se la chiave non esiste, restituisce None
        return None

# Recupera il flow_id corrente da Redis
current_flow_id = r.get(machine_id)
if current_flow_id is not None:
    current_flow_id = int(current_flow_id)
    print(f"Flow ID corrente: {current_flow_id}")

    # Aggiorna la mappa eBPF con il valore attuale di current_flow_id
    flow_map[0] = current_flow_id

# Loop infinito per aggiornare Redis con il flow_id corrente
while True:
    current_flow_id = get_current_flow_id()
    
    if current_flow_id is not None:
        print(f"Flow ID corrente: {current_flow_id}")
        
        r.set(machine_id, current_flow_id)
    
    time.sleep(10)
