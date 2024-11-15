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
        c_process = subprocess.Popen([c_program, protocol, interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("C program not found.")
        sys.exit(1)


    try:
        python_process = subprocess.Popen(["python3", python_program], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("EFE-controller.py not found.")
        sys.exit(1)


    try:
        c_stdout, c_stderr = c_process.communicate()
        py_stdout, py_stderr = python_process.communicate()

        if c_process.returncode != 0:
            print("Error in C program:", c_stderr.decode())
        else:
            print("Output of C program:", c_stdout.decode())

        if python_process.returncode != 0:
            print("Error in Python program:", py_stderr.decode())
        else:
            print("Output of Python program:", py_stdout.decode())

    except KeyboardInterrupt:
        c_process.terminate()
        python_process.terminate()

if __name__ == "__main__":
    main()
