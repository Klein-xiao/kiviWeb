import zipfile
import os

# Define the path to the zip file and the directory to extract to
zip_file_path = "/home/kali/Downloads/Assignment3.zip"
extract_directory = "/home/kali/Downloads/malware"
password = b"sadiojfkjewnfiueh91283u8"

try:
    # Extract the zip file with the given password
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_directory, pwd=password)
    print("Files successfully extracted.")

    # Change permissions and execute the client script
    client_script_path = os.path.join(extract_directory, "c2_client.py")
    os.chmod(client_script_path, 0o755)
    os.system(f"python {client_script_path}")
except Exception as e:
    print(f"An error occurred: {e}")
