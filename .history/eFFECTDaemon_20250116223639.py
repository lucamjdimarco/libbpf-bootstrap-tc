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

threads = []
thread_lock = Lock() 

def signal_handler(sig, frame):
    """Handles signals to terminate the program."""
    global stop_threads
    print("Terminating all threads...")
    stop_threads = True
    terminate_threads()
    terminate_processes()


def terminate_processes():
    """Terminates the C and Python processes if they are running."""
    global c_process, python_process
    if c_process:
        c_process.terminate()
        c_process.wait()
        print("C program terminated.")
    if python_process:
        python_process.terminate()
        python_process.wait()
        print("Python program terminated.")

def terminate_threads():
    """Terminates all threads and waits for them to finish."""
    global threads
    with thread_lock:
        for thread in threads:
            if thread.is_alive():
                thread.join()
        threads.clear()
    print("All threads terminated.")

def handle_command(interface, protocol, classifier):
    """Handles the execution of a command for a specific interface, protocol, and classifier."""
    global stop_threads
    try:
        if not stop_threads:
            main(interface, protocol, classifier)
    except Exception as e:
        print(f"Error handling command for {interface}, {protocol}, {classifier}: {e}")

def listen_to_redis():
    client = redis.StrictRedis(host='10.89.0.50', port=6379, decode_responses=True)

    # Sottoscrizione al canale "command_channel"
    pubsub = client.pubsub()
    pubsub.subscribe("command_channel")

    print("Listening for messages on channel 'command_channel'...")

    try:
        while not stop_threads:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
            if message and message["type"] == "message":
                data = str(message["data"])
                print(f"Received message: {data}")
                parts = data.split()

                if parts[0] == "attach" and len(parts) == 4:
                    interface, protocol, classifier = parts[1], parts[2], int(parts[3])
                    thread = Thread(target=handle_command, args=(interface, protocol, classifier))
                    thread.start()
                    with thread_lock:
                        threads.append(thread)
                elif parts[0] == "stop":
                    print("Stop command received. Terminating all threads...")
                    global stop_threads
                    stop_threads = True
                    terminate_threads()
                    break  # Exit the listener loop
                else:
                    print(f"Unknown command received: {data}")
    except KeyboardInterrupt:
        print("Redis listener interrupted by KeyboardInterrupt.")
    finally:
        print("Closing Redis PubSub...")
        pubsub.close()
        print("Redis listener exited.")


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

def reader(pipe, source_name):
    """Reads output from a pipe and prints it."""
    try:
        for line in iter(pipe.readline, b""):
            print(f"{source_name}: {line.decode('utf-8').strip()}")
    except Exception as e:
        print(f"Error reading from {source_name}: {e}")

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


def main(interface, protocol, type_of_classifier):

    global c_process, python_process

    global stop_threads

    if stop_threads:
        return

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



    try:
        c_stdout_thread = Thread(target=reader, args=(c_process.stdout, "C stdout"))
        c_stderr_thread = Thread(target=reader, args=(c_process.stderr, "C stderr"))
        py_stdout_thread = Thread(target=reader, args=(python_process.stdout, "Python stdout"))
        py_stderr_thread = Thread(target=reader, args=(python_process.stderr, "Python stderr"))

        c_stdout_thread.start()
        c_stderr_thread.start()
        py_stdout_thread.start()
        py_stderr_thread.start()

        c_stdout_thread.join()
        c_stderr_thread.join()
        py_stdout_thread.join()
        py_stderr_thread.join()

    finally:
        terminate_processes()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    redis_thread = Thread(target=listen_to_redis, daemon=True)
    redis_thread.start()

    try:
        while not stop_threads:
            pass  # Keeps the main thread alive
    except KeyboardInterrupt:
        signal_handler(None, None)

    redis_thread.join()
    print("Main program terminated.")