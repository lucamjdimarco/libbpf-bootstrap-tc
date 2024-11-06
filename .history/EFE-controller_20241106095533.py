import redis
import time
import os
import ctypes

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

# Percorso alla mappa eBPF (assumendo che sia montata qui)
BPF_MAP_PATH = "/sys/fs/bpf/flowpy_map"  # Cambia questo con il percorso esatto della tua mappa

# Inizializza la chiave machine_id in Redis con valore 0, se non esiste
if r.get(machine_id) is None:
    r.set(machine_id, 0)

# Funzione per recuperare l'ultimo flow_id dalla mappa eBPF
def get_current_flow_id():
    try:
        # Apri il file di mappa in modalità binaria
        with open(BPF_MAP_PATH, "rb") as f:
            # Definisci il formato e leggi la chiave e il valore
            key = ctypes.c_int(0)  # Chiave 0 come esempio
            value = ctypes.c_int()
            f.seek(key.value * ctypes.sizeof(ctypes.c_int))  # Posizionati all'indice della chiave
            value.value = int.from_bytes(f.read(ctypes.sizeof(ctypes.c_int)), "little")
            return value.value
    except FileNotFoundError:
        print("Mappa eBPF non trovata nel percorso specificato.")
        return None

# Loop infinito per aggiornare Redis con il flow_id corrente
while True:
    current_flow_id = get_current_flow_id()
    
    if current_flow_id is not None:
        print(f"Flow ID corrente: {current_flow_id}")
        r.set(machine_id, current_flow_id)
    
    time.sleep(10)
