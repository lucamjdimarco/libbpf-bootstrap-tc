from bcc import BPF
import redis
import time
import os

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

# Inizializza il programma eBPF
b = BPF(src_file="tc.bpf.c")

# Recupera la mappa eBPF
flow_map = b.get_table("flowpy_map")

# Funzione per recuperare l'ultimo flow_id dalla mappa eBPF
def get_current_flow_id():
    try:
        # Chiave della mappa (machine-id o ID univoco del container)
        key = flow_map.Key(int(machine_id, 16))  # Converti machine_id in un intero
        value = flow_map[key]  # Recupera il valore dalla mappa
        return value.value  # Restituisce il flow_id
    except KeyError:
        # Se la chiave non esiste, restituisce None
        return None

# Ciclo per monitorare la mappa e aggiornare periodicamente Redis
while True:
    current_flow_id = get_current_flow_id()
    
    if current_flow_id is not None:
        print(f"Flow ID corrente: {current_flow_id}")
        
        # Aggiorna Redis con il flow_id corrente
        r.set(machine_id, current_flow_id)
    
    # Aspetta 10 secondi prima di fare il prossimo aggiornamento
    time.sleep(10)
