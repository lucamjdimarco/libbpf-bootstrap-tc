import redis
import time
import os

from typing import Coroutine
import settings
import subprocess
import os
import json
from hex_types import u64, u32, u16, u8, s8, to_hex

# Inizializza la connessione a Redis
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()


# Verifica se la mappa è presente
# try:
#     flow_map = b.get_table("flowpy_map")
# except KeyError:
#     print("Mappa 'flowpy_map' non trovata.")
#     exit(1) 

# Funzione per recuperare il flow_id corrente
# def get_current_flow_id():
#     try:
#         key = 0 
#         value = flow_map[key] 
#         return value.value  
#     except KeyError:
#         return None

# Loop per leggere il flow_id e aggiornarlo in Redis
# while True:
#     current_flow_id = get_current_flow_id()
#     if current_flow_id is not None:
#         print(f"Flow ID corrente: {current_flow_id}")
#         r.set(machine_id, current_flow_id)
#     time.sleep(10)
