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

    c_program = ['./tc', interface, protocol]
    python_program = ['python3', 'EFE-controller.py']


    if not os.path.isfile(c_program):
        print(f"C program '{c_program}' does not exist.")
        sys.exit(1)


    try:
        c_result = subprocess.run(c_program, capture_output=True, text=True, check=True)
        print("Output of C program:")
        print(c_result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error occurred while running the C program:")
        print(e.stderr)

    # Esegui il programma Python
    try:
        python_result = subprocess.run(python_program, capture_output=True, text=True, check=True)
        print("Output of Python program:")
        print(python_result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error occurred while running the Python program:")
        print(e.stderr)

if __name__ == "__main__":
    main()
