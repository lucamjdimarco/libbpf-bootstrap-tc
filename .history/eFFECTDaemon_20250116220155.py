import argparse
import subprocess
import sys
import os
from threading import Thread, Lock
from queue import Queue
import redis
import signal
from settings import BPF_FS_PATH



friendlyname = ""
r = redis.Redis(host='redis', port=6379, db=0)
machine_id = os.popen("cat /etc/machine-id").read().strip()
c_process = None
python_process = None

stop_threads = False

threads = []  # Lista per tenere traccia dei thread attivi
thread_lock = Lock() 

def signal_handler(sig, frame):
    """Gestisce i segnali per terminare il programma."""
    global stop_threads
    print("Terminating all threads...")
    stop_threads = True 
    terminate_threads()

def handle_command(interface, protocol, classifier):
    """Gestisce la compilazione ed esecuzione del programma per un comando specifico."""
    try:
        execute_make(classifier)
        main(interface, protocol, classifier)
    except Exception as e:
        print(f"Error handling command for {interface}, {protocol}, {classifier}: {e}")

def listen_to_redis():
    client = redis.StrictRedis(host='10.89.0.50', port=6379, decode_responses=True)

    # Sottoscrizione al canale "command_channel"
    pubsub = client.pubsub()
    pubsub.subscribe("command_channel")

    print("Listening for messages on channel 'command_channel'...")

    for message in pubsub.listen():
        if message['type'] == 'message':
            try:
                data = str(message['data'])
                print(f"Received message: {data}")
                parts = data.split()
                command = parts[0]
                if command == "attach" and len(parts) == 4:
                    interface = parts[1]
                    protocol = parts[2]
                    classifier = int(parts[3])
                    
                    
                    thread = Thread(target=handle_command, args=(interface, protocol, classifier))
                    thread.start()
                    with thread_lock:
                        threads.append(thread)
                else:
                    print(f"Invalid command format: {data}")
            except Exception as e:
                print(f"Error processing message: {e}")

# Mount the bpf filesystem - Function passed from EFE-controller.py
def mount_bpf(mount_point):
    """
    mount -t bpf bpf /sys/fs/bpf/
    """
    # Everything that is private to the bash process that will be launch
    # mount the bpf filesystem.
    # Note: childs of the launching (parent) bash can access this instance
    # of the bpf filesystem. If you need to get access to the bpf filesystem
    # (where maps are available), you need to use nsenter with -m and -t
    # that points to the pid of the parent process (launching bash).
    cmd = f"grep -qs '{mount_point} ' /proc/mounts || mount -t bpf bpf {mount_point}"
    print(f"Exec: {cmd}")
    ret = os.system(cmd)
    if ret:
        raise OSError(f"Can not mount BPF fs on {mount_point}")

# def set_friendlyname():
#     global friendlyname
#     try:
#         # Check if a value exists for the machine_id
#         existing_value = r.get(machine_id)
#         if existing_value:
        
#             friendlyname = existing_value.decode('utf-8')
#             print(f"Friendlyname already exists for Machine ID '{machine_id}': {friendlyname}")
#         else:
        
#             friendlyname = input("Enter a friendlyname for the machine: ")
#             r.set(machine_id, friendlyname)
#             print(f"Friendlyname '{friendlyname}' saved for Machine ID '{machine_id}'!")

#     except Exception as e:
#         print(f"An error occurred: {e}")

def retrieve_friendlyname():
    global friendlyname
    try:
        existing_value = r.get(machine_id)
        if existing_value:
            friendlyname = existing_value.decode('utf-8')
            print(f"Friendlyname already exists for Machine ID '{machine_id}': {friendlyname}")
        else:
            print(f"Error: No friendlyname found for Machine ID '{machine_id}'.")
            sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

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

def execute_make(type_of_classifier):
    try:
        # Save the current directory
        current_dir = os.getcwd()
        
        # Change to the target directory
        os.chdir("src/c")

        # Clean build artifacts
        print("Running 'make clean'...")
        clean_result = subprocess.run(
            ["make", "clean"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if clean_result.returncode == 0:
            print("'make clean' completed successfully.")
        else:
            print("'make clean' failed.")
            print("Error:")
            print(clean_result.stderr)
            sys.exit(1)

        # Compile the program with the provided classifier
        cflags_extra = f"CFLAGS_EXTRA=-DCLASS={type_of_classifier}"
        command = ["make", "-j6", cflags_extra]
        
        print(f"Running command: {' '.join(command)}")
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        
        if result.returncode == 0:
            print("Command executed successfully.")
            print("Output:")
            print(result.stdout)
        else:
            print("Command failed.")
            print("Error:")
            print(result.stderr)
            sys.exit(1)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Return to the original directory
        os.chdir(current_dir)

def terminate_threads():
    """Terminates all threads and waits for them to finish."""
    global threads
    with thread_lock:
        for thread in threads:
            if thread.is_alive():
                thread.join()
        threads.clear()
    print("All threads terminated.")

def terminate_processes(signum, frame):
    """Handler per la terminazione dei processi e dei thread."""
    terminate_threads()
    sys.exit(0)

# def terminate_processes(signum, frame):
#     """Terminate both the C and Python processes gracefully."""
#     global c_process, python_process

#     print("\nGraceful termination initiated.")
#     if c_process:
#         c_process.terminate()
#         c_process.wait()
#         print("C program terminated.")

#     if python_process:
#         python_process.terminate()
#         python_process.wait()
#         print("Python program terminated.")

#     sys.exit(0)


def main(interface, protocol, type_of_classifier):

    global c_process, python_process

    global stop_threads
    
    #signal.signal(signal.SIGINT, terminate_processes)  # Handle Ctrl+C
    #signal.signal(signal.SIGTERM, terminate_processes)  # Handle termination signals

    # parser = argparse.ArgumentParser(description="Exec C program and Python program")
    # parser.add_argument("interface", help="Specify the interface to monitor.")
    # parser.add_argument("protocol", choices=["ipv4", "ipv6"], help="Specify the protocol (ipv4 or ipv6).")
    # parser.add_argument("type_of_classifier", choices=["1","2","3","4","5","6"], help="Specify the classifier to use.")

    # args = parser.parse_args()
    # protocol = args.protocol
    # interface = args.interface
    # type_of_classifier = args.type_of_classifier

    if interface == "eth0":
        print("Error: eBPF instance cannot be started on interface 'eth0'.")
        sys.exit(1)

    try:
        mount_bpf(BPF_FS_PATH)
        print(f"BPF filesystem mounted on {BPF_FS_PATH}")
    except OSError as e:
        print(f"Error mounting BPF filesystem: {e}")
        exit(1)

    retrieve_friendlyname()

    c_program_path = os.path.abspath(os.path.join("src", "c", "tc"))
    python_program = "EFE-controller.py"

    execute_make(type_of_classifier)

    #os.chdir("../..") 

    if not os.path.isfile(c_program_path):
        print(f"C program '{c_program_path}' does not exist.")
        sys.exit(1)

    try:
        c_process = subprocess.Popen(
            [c_program_path, interface, protocol, friendlyname],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1, 
            #text=True,
        )
    except FileNotFoundError:
        print("C program not found.")
        sys.exit(1)
    
    try:
        python_process = subprocess.Popen(
            ["python3", "-u", python_program, interface, protocol, str(type_of_classifier)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1, 
            #text=True,
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
        
        while True:
            c_stdout = c_stdout_queue.get()
            c_stderr = c_stderr_queue.get()
            py_stdout = py_stdout_queue.get()
            py_stderr = py_stderr_queue.get()


            if c_stdout is None and c_stderr is None and py_stdout is None and py_stderr is None:
                break

            if c_stdout is not None:
                print(f"{c_stdout[0]}: {c_stdout[1]}")
            if c_stderr is not None:
                print(f"{c_stderr[0]}: {c_stderr[1]}")
            if py_stdout is not None:
                print(f"{py_stdout[0]}: {py_stdout[1]}")
            if py_stderr is not None:
                print(f"{py_stderr[0]}: {py_stderr[1]}")

    except KeyboardInterrupt:
        terminate_processes(None, None)


    c_exit_code = c_process.wait()
    python_exit_code = python_process.wait()

    if c_exit_code != 0:
        print(f"C program finished with error code {c_exit_code}")
    if python_exit_code != 0:
        print(f"Python program finished with error code {python_exit_code}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, terminate_processes)
    signal.signal(signal.SIGTERM, terminate_processes)
    listen_to_redis()
