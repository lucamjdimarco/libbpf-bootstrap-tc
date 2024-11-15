import argparse
import subprocess
import sys
import os

def main():
    
    parser = argparse.ArgumentParser(description="Exec C program and Pythoin program")
    parser.add_argument("protocol", choices=["ipv4", "ipv6"], help="Specifica il protocollo (ipv4 o ipv6).")
    parser.add_argument("interface", help="Specifica il nome dell'interfaccia di rete.")

    args = parser.parse_args()
    protocol = args.protocol
    interface = args.interface

    # Percorso relativo al programma C
    c_program = os.path.join("src", "c", "tc")

    # Verifica che il file esista
    if not os.path.isfile(c_program):
        print(f"Il programma C '{c_program}' non esiste. Verifica il percorso.")
        sys.exit(1)

    # Esegui il programma C
    try:
        c_process = subprocess.Popen([c_program, protocol, interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("Il programma C non è stato trovato. Verifica il percorso.")
        sys.exit(1)

    # Monitora il processo
    try:
        c_stdout, c_stderr = c_process.communicate()

        if c_process.returncode != 0:
            print("Errore nel programma C:", c_stderr.decode())
        else:
            print("Output programma C:", c_stdout.decode())

    except KeyboardInterrupt:
        # Termina il processo in caso di interruzione manuale
        c_process.terminate()

if __name__ == "__main__":
    main()
