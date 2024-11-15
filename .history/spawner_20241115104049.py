import argparse
import subprocess
import sys
import os

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
        c_process = subprocess.Popen([c_program, interface, protocol], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print("C program not found.")
        sys.exit(1)


    try:
        python_process = subprocess.Popen(["python3", python_program], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print("EFE-controller.py not found.")
        sys.exit(1)


    try:
        while True:
            
            c_stdout = c_process.stdout.readline()
            if c_stdout:
                print("Output of C program:", c_stdout.strip())
            
            
            py_stdout = python_process.stdout.readline()
            if py_stdout:
                print("Output of Python program:", py_stdout.strip())

            
            c_stderr = c_process.stderr.readline()
            if c_stderr:
                try:
                    print("Error in C program:", c_stderr.strip())
                except UnicodeDecodeError:
                    print("Error in C program (unable to decode):", repr(c_stderr))

            # Gestione della stderr del programma Python
            py_stderr = python_process.stderr.readline()
            if py_stderr:
                try:
                    print("Error in Python program:", py_stderr.strip())
                except UnicodeDecodeError:
                    print("Error in Python program (unable to decode):", repr(py_stderr))

            
            if c_process.poll() is not None and python_process.poll() is not None:
                break

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
