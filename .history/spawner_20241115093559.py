import subprocess
import sys
import os

# Esegui il programma C BPF
c_program = "./tc"
protocol = "<ipv4 o ipv6>"  # Sostituisci con "ipv4" o "ipv6"
interface = "<interfaccia>"  # Sostituisci con il nome dell'interfaccia

try:
    c_process = subprocess.Popen([c_program, protocol, interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    print("Il programma C non è stato trovato. Verifica il percorso.")
    sys.exit(1)

# Esegui il programma Python
python_script = "your_script.py"  # Sostituisci con il percorso del tuo script Python

try:
    python_process = subprocess.Popen([sys.executable, python_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except FileNotFoundError:
    print("Il programma Python non è stato trovato. Verifica il percorso.")
    c_process.terminate()
    sys.exit(1)

# Monitora i processi
try:
    c_stdout, c_stderr = c_process.communicate()
    py_stdout, py_stderr = python_process.communicate()
    
    if c_process.returncode != 0:
        print("Errore nel programma C:", c_stderr.decode())
    if python_process.returncode != 0:
        print("Errore nel programma Python:", py_stderr.decode())

except KeyboardInterrupt:
    # Termina entrambi i processi in caso di interruzione manuale
    c_process.terminate()
    python_process.terminate()
