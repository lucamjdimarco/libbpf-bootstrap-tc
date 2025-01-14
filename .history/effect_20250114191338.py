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
    - Se non viene passato un HFN e su Redis non esiste un valore per quel machin-id, restituisce errore.
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


def main():
    parser = argparse.ArgumentParser(description="Gestione dei comandi per il programma.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Parser per il comando "start"
    start_parser = subparsers.add_parser("start", help="Comando per avviare il processo con un Human Friendly Name.")
    start_parser.add_argument("hfn", nargs="?", help="Human Friendly Name (opzionale).")

    # Parser per "attach"
    attach_parser = subparsers.add_parser("attach", help="Attach probe.")
    attach_parser.add_argument("interface", help="Specify the interface to monitor.")
    attach_parser.add_argument("protocol", choices=["ipv4", "ipv6"], help="Specify the protocol (ipv4 or ipv6).")
    attach_parser.add_argument("type_of_classifier", choices=["1","2","3","4","5","6"], help="Specify the classifier to use.")


    args = parser.parse_args()

    if args.command == "start":
        check_hfn(args.hfn)
    elif args.command == "attach":
        print("Attaching probe...")
        send_command(interface, protocol, type_of_classifier)

if __name__ == "__main__":
    main()