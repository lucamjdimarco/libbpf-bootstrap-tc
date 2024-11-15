import argparse
import subprocess
import sys
import os
from threading import Thread
from queue import Queue

def reader(pipe, queue):
    try:
        with pipe:
            for line in iter(pipe.readline, b''): 
                queue.put((pipe, line)) 
    finally:
        queue.put(None) 

def main(): 

    parser = argparse.ArgumentParser(description="Exec C program and Python program")
    parser.add_argument("protocol", choices=["ipv4", "ipv6"], help="Specify the protocol (ipv4 or ipv6).")
    parser.add_argument("interface", help="Specify the interface to monitor.")

    args = parser.parse_args()
    protocol = args.protocol
    interface = args.interface


    c_program = os.path.join("src", "c", "tc")
    python_program = "EFE-controller.py"


    if not os.path.isfile(c_program):
        print(f"C program '{c_program}' does not exist.")
        sys.exit(1)


    try:
        c_process = subprocess.Popen([c_program, interface, protocol], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, text=True)
    except FileNotFoundError:
        print("C program not found.")
        sys.exit(1)


    try:
        python_process = subprocess.Popen(["python3", python_program], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, text=True)
    except FileNotFoundError:
        print("EFE-controller.py not found.")
        sys.exit(1)
    



    try:
        c_stdout_queue = Queue()
        c_stderr_queue = Queue()
        c_stdout_thread = Thread(target=reader, args=[c_process.stdout, c_stdout_queue])
        c_stderr_thread = Thread(target=reader, args=[c_process.stderr, c_stderr_queue])
        c_stdout_thread.start()
        c_stderr_thread.start()

        python_stdout_queue = Queue()
        python_stderr_queue = Queue()
        python_stdout_thread = Thread(target=reader, args=[python_process.stdout, python_stdout_queue])
        python_stderr_thread = Thread(target=reader, args=[python_process.stderr, python_stderr_queue])
        python_stdout_thread.start()
        python_stderr_thread.start()

        while True:
            c_stdout = c_stdout_queue.get()
            c_stderr = c_stderr_queue.get()
            python_stdout = python_stdout_queue.get()
            python_stderr = python_stderr_queue.get()

            if c_stdout is None and c_stderr is None and python_stdout is None and python_stderr is None:
                break

            if c_stdout is not None:
                print(f"C stdout: {c_stdout[1]}", end="")
            if c_stderr is not None:
                print(f"C stderr: {c_stderr[1]}", end="")
            if python_stdout is not None:
                print(f"Python stdout: {python_stdout[1]}", end="")
            if python_stderr is not None:
                print(f"Python stderr: {python_stderr[1]}", end="")

    except KeyboardInterrupt:
        print("Process interrupted.")
        c_process.terminate()
        python_process.terminate()

    if c_process.returncode != 0:
        print(f"C program finished with error code {c_process.returncode}")
    if python_process.returncode != 0:
        print(f"Python program finished with error code {python_process.returncode}")

if __name__ == "__main__":
    main()
