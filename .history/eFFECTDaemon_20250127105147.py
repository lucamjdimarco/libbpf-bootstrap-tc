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

pubsub = None

def signal_handler(sig, frame):
    """Handles signals to terminate the program."""
    global stop_threads
    print("Signal received. Initiating termination...")
    stop_threads = True

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
                thread.join(timeout=1)  
        threads.clear()
    print("All threads terminated.")

def handle_command(interface, protocol, classifier):
    """Executes the main command for a specific interface, protocol, and classifier."""
    try:
        main(interface, protocol, classifier)
    except Exception as e:
        print(f"Error handling command: {e}")

def listen_to_redis():
    """Listens to Redis for incoming commands."""
    global stop_threads, pubsub
    client = redis.StrictRedis(host='redis', port=6379, decode_responses=True)
    pubsub = client.pubsub()
    pubsub.subscribe("command_channel")

    print("Listening for messages on channel 'command_channel'...")

    try:
        while not stop_threads:
            message = pubsub.get_message(ignore_subscribe_messages=True, timeout=1)
            if message and message["type"] == "message":
                handle_redis_message(message["data"])
    except Exception as e:
        print(f"Error in Redis listener: {e}")
    finally:
        close_redis()

def handle_redis_message(data):
    """Processes a Redis message."""
    global stop_threads
    print(f"Received message: {data}")
    parts = data.split()

    if parts[0] == "attach" and len(parts) == 4:
        interface, protocol, classifier = parts[1], parts[2], int(parts[3])
        thread = Thread(target=handle_command, args=(interface, protocol, classifier))
        thread.start()
        with thread_lock:
            threads.append(thread)
    elif parts[0] == "stop":
        print("Stop command received. Terminating all threads and processes...")
        stop_threads = True
    else:
        print(f"Unknown command received: {data}")
    
def close_redis():
    """Closes the Redis PubSub connection."""
    global pubsub
    if pubsub:
        try:
            pubsub.close()
            print("Redis PubSub connection closed.")
        except Exception as e:
            print(f"Error closing Redis PubSub: {e}")


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

def reader(pipe, source_name, queue):
    """Reads output from a pipe and prints it."""
    # try:
    #     for line in iter(pipe.readline, b""):
    #         print(f"{source_name}: {line.decode('utf-8').strip()}")
    # except Exception as e:
    #     print(f"Error reading from {source_name}: {e}")
    try:
        for line in iter(pipe.readline, b""):
            queue.put(f"{source_name}: {line.decode('utf-8').strip()}")
    except Exception as e:
        print(f"Error reading from {source_name}: {e}")


#######
def process_output(queue):
    """Processes the output from the queue."""
    while not stop_threads or not queue.empty():
        try:
            message = queue.get(timeout=1)
            print(message)
        except Exception:
            continue

#######

def execute_make(type_of_classifier):
    """Builds the BPF program with the specified classifier."""
    try:
        os.chdir("src/c")
        subprocess.run(["make", "clean"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["make", "-j6", f"CFLAGS_EXTRA=-DCLASS={type_of_classifier}"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Build completed for classifier {type_of_classifier}.")
    except subprocess.CalledProcessError as e:
        print(f"Build error: {e.stderr.decode('utf-8')}")
    finally:
        os.chdir("../../")


def main(interface, protocol, classifier):
    """Main function to start the BPF program and related processes."""
    global c_process, python_process, stop_threads
    #####
    output_queue = Queue()
    ######

    if stop_threads:
        return

    if interface == "eth0":
        print("Error: eBPF cannot be started on 'eth0'.")
        sys.exit(1)

    mount_bpf(BPF_FS_PATH)
    retrieve_friendlyname()
    execute_make(classifier)

    try:
        c_program_path = os.path.abspath("src/c/tc")
        python_program = os.path.abspath("EFE-controller.py")

        if not os.path.isfile(c_program_path):
            raise FileNotFoundError(f"C program '{c_program_path}' not found.")
        if not os.path.isfile(python_program):
            raise FileNotFoundError(f"Python program '{python_program}' not found.")

        c_process = subprocess.Popen([c_program_path, interface, protocol, friendlyname], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)
        python_process = subprocess.Popen(["python3", "-u", python_program, interface, protocol, str(classifier)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)

        Thread(target=reader, args=(c_process.stdout, "C stdout")).start()
        Thread(target=reader, args=(c_process.stderr, "C stderr")).start()
        Thread(target=reader, args=(python_process.stdout, "Python stdout")).start()
        Thread(target=reader, args=(python_process.stderr, "Python stderr")).start()
    except Exception as e:
        print(f"Error starting processes: {e}")
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
    terminate_threads()
    terminate_processes()
    print("Program terminated.")
    