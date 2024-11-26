import argparse
import subprocess
import sys
import os
from threading import Thread
from queue import Queue

def reader(pipe, queue, source_name):
    """Legge l'output da una pipe e lo mette in una coda."""
    try:
        for line in iter(pipe.readline, b''): 
            if line:
                decoded_line = line.decode("utf-8", errors="replace").strip()  
                print(f"Debug {source_name}: {decoded_line}") 
                queue.put((source_name, decoded_line))
    except Exception as e:
        print(f"Errore durante la lettura da {source_name}: {e}")
    finally:
        queue.put(None)

def main():
    parser = argparse.ArgumentParser(description="Exec C program and Python program")
    parser.add_argument("interface", help="Specify the interface to monitor.")
    parser.add_argument("protocol", choices=["ipv4", "ipv6"], help="Specify the protocol (ipv4 or ipv6).")

    args = parser.parse_args()
    protocol = args.protocol
    interface = args.interface

    c_program = os.path.join("src", "c", "tc")
    python_program = "EFE-controller.py"

    if not os.path.isfile(c_program):
        print(f"C program '{c_program}' does not exist.")
        sys.exit(1)

    try:
        c_process = subprocess.Popen(
            [c_program, interface, protocol],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1, 
        )
    except FileNotFoundError:
        print("C program not found.")
        sys.exit(1)

    try:
        python_process = subprocess.Popen(
            ["python3", python_program, interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1, 
        )
    except FileNotFoundError:
        print("EFE-controller.py not found.")
        sys.exit(1)


    c_stdout_queue = Queue()
    c_stderr_queue = Queue()
    py_stdout_queue = Queue()
    py_stderr_queue = Queue()

    # Thread per leggere i flussi
    Thread(target=reader, args=[c_process.stdout, c_stdout_queue, "C stdout"]).start()
    Thread(target=reader, args=[c_process.stderr, c_stderr_queue, "C stderr"]).start()
    Thread(target=reader, args=[python_process.stdout, py_stdout_queue, "Py stdout"]).start()
    Thread(target=reader, args=[python_process.stderr, py_stderr_queue, "Py stderr"]).start()

    try:
        # Loop principale per leggere e stampare i dati in tempo reale
        while True:
            c_stdout = c_stdout_queue.get()
            c_stderr = c_stderr_queue.get()
            py_stdout = py_stdout_queue.get()
            py_stderr = py_stderr_queue.get()

            # Interrompi il ciclo se entrambi i processi hanno terminato
            if c_stdout is None and c_stderr is None and py_stdout is None and py_stderr is None:
            #if c_stdout is None and c_stderr is None:
                break

            if c_stdout is not None:
                print(f"{c_stdout[0]}: {c_stdout[1]}", end="")
            if c_stderr is not None:
                print(f"{c_stderr[0]}: {c_stderr[1]}", end="")
            if py_stdout is not None:
                print(f"{py_stdout[0]}: {py_stdout[1]}", end="")
            if py_stderr is not None:
                print(f"{py_stderr[0]}: {py_stderr[1]}", end="")

    except KeyboardInterrupt:
        print("Process interrupted.")
        c_process.terminate()
        python_process.terminate()

    # Controlla i codici di ritorno
    c_exit_code = c_process.wait()
    python_exit_code = python_process.wait()

    if c_exit_code != 0:
        print(f"C program finished with error code {c_exit_code}")
    if python_exit_code != 0:
        print(f"Python program finished with error code {python_exit_code}")

if __name__ == "__main__":
    main()
