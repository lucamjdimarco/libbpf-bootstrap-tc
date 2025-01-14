import redis
import sys
import os
import argparse

r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()


def set_friendlyname(hfn):
    global friendlyname
    try:
        # Check if a value exists for the machine_id
        existing_value = r.get(machine_id)
        if existing_value:
        
            friendlyname = existing_value.decode('utf-8')
            print(f"Friendlyname already exists for Machine ID '{machine_id}': {friendlyname}")
        else:
    
            friendlyname = hfn
            r.set(machine_id, friendlyname)
            print(f"Friendlyname '{friendlyname}' saved for Machine ID '{machine_id}'!")

    except Exception as e:
        print(f"An error occurred: {e}")



def check_hfn(hfn=None):
    """
    Controlla l'Human Friendly Name (HFN):
    - Se non esiste un HFN su Redis per il machine_id, lo imposta.
    - Se esiste un HFN diverso da quello passato, restituisce errore.
    - Se non viene passato un HFN e su Redis non esiste un valore, restituisce errore.
    """
    try:
        existing_value = r.get(machine_id)

        if hfn:
            
            if existing_value:
                stored_hfn = existing_value.decode('utf-8')
                if stored_hfn != hfn:
                    print(f"Errore: Friendlyname passato '{hfn}' non corrisponde a quello salvato '{stored_hfn}' per Machine ID '{machine_id}'.")
                    sys.exit(1)
                else:
                    print(f"Friendlyname '{stored_hfn}' confermato per Machine ID '{machine_id}'.")
            else:
                
                set_friendlyname(hfn)
        else:
            
            if existing_value:
                stored_hfn = existing_value.decode('utf-8')
                print(f"Friendlyname '{stored_hfn}' già salvato per Machine ID '{machine_id}'.")
            else:
                print(f"Errore: Nessun Friendlyname salvato per Machine ID '{machine_id}', e nessun valore passato.")
                sys.exit(1)
    except Exception as e:
        print(f"Si è verificato un errore: {e}")
        sys.exit(1)
