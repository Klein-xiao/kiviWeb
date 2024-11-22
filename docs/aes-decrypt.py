import argparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import sys
import binascii

def aes_decrypt(key, iv, mode, ciphertext_file, plaintext_file, gcm_arg=None):
    # read key
    with open(key, 'r') as f:
        key = binascii.unhexlify(f.read().strip())  # hex -> byte
    print(f"key: {key.hex()}")
    # read input_file
    with open(ciphertext_file, 'rb') as f:
        ciphertext = f.read()
    print("--------------decrypt-------------")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Ciphertext Length: {len(ciphertext)}")
    # chose mode of AES
    if mode == 'ecb':
        cipher_mode = modes.ECB()
    elif mode == 'cbc':
        with open(iv, 'r') as f:
            iv = binascii.unhexlify(f.read().strip())  # CBC mode need IV
        cipher_mode = modes.CBC(iv)
    elif mode == 'gcm':
        with open(iv, 'r') as f:
            iv = binascii.unhexlify(f.read().strip())
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]
        print(f"Extracted Ciphertext (without tag): {ciphertext.hex()}")
        print(f"Extracted Tag: {tag.hex()}")
        print(f"Tag Length: {len(tag)}")
        cipher_mode = modes.GCM(iv, tag)  # split tag
    else:
        raise ValueError('Invalid mode. Use ecb or cbc or gcm')

    # create AES decrypt Cipher
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()

    # GCM mode need additional data
    if mode == 'gcm' and gcm_arg:
        with open(gcm_arg, 'rb') as f:
            additional_data = f.read()
        decryptor.authenticate_additional_data(additional_data)

    # decrypt data
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # remove padding
    if mode != 'gcm':
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

    # output plaintext
    with open(plaintext_file, 'wb') as f:
        f.write(plaintext)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AES Decryption Script")
    parser.add_argument("-key", required=True, help="Key file path")
    parser.add_argument("-IV", required=False, help="IV file path (required for CBC and GCM)")
    parser.add_argument("-mode", required=True, choices=['ecb', 'cbc', 'gcm'], help="AES mode (ecb, cbc, or gcm)")
    parser.add_argument("-input", required=True, help="Ciphertext input file path")
    parser.add_argument("-out", required=True, help="Plaintext output file path")
    parser.add_argument("-gcm_arg", required=False, help="Additional authenticated data (AAD) file path for GCM")

    args = parser.parse_args()

    aes_decrypt(args.key, args.IV, args.mode, args.input, args.out, args.gcm_arg)