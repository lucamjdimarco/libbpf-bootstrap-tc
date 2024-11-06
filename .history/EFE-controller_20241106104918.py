from bcc import BPF
import redis
import time
import os

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()

# Inizializza BPF senza compilare il codice, solo per interagire con la mappa
b = BPF(text="int _start() { return 0; }")

# Verifica se la mappa è presente
try:
    flow_map = b.get_table("flowpy_map")
except KeyError:
    print("Mappa 'flowpy_map' non trovata.")
    exit(1)  # Esci se la mappa non è trovata

# Funzione per recuperare il flow_id corrente
def get_current_flow_id():
    try:
        key = 0  # La chiave che stai usando
        value = flow_map[key]  # Ottieni il valore associato a quella chiave
        return value.value  # Restituisce il valore
    except KeyError:
        return None

# Loop per leggere il flow_id e aggiornarlo in Redis
while True:
    current_flow_id = get_current_flow_id()
    if current_flow_id is not None:
        print(f"Flow ID corrente: {current_flow_id}")
        r.set(machine_id, current_flow_id)
    time.sleep(10)
