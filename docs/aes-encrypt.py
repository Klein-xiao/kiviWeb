import argparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import binascii

def aes_encrypt(key, iv, mode, plaintext_file, ciphertext_file, gcm_arg=None):
    # read key
    with open(key, 'r') as f:
        key = binascii.unhexlify(f.read().strip()) # hex -> byte

    # read input_file
    with open(plaintext_file, 'rb') as f:
        plaintext = f.read()

    # PKCS7 padding
    if mode != 'gcm':
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
    else:
        padded_data = plaintext

    # chose mode of AES
    if mode == 'ecb':
        cipher_mode = modes.ECB()
    elif mode == 'cbc':
        with open(iv, 'r') as f:
            iv = binascii.unhexlify(f.read().strip()) # CBC mode need IV
        cipher_mode = modes.CBC(iv)
    elif mode == 'gcm':
        with open(iv, 'r') as f:
            iv = binascii.unhexlify(f.read().strip())
        cipher_mode = modes.GCM(iv)
    else:
        raise ValueError('Invalid mode. Use ecb or cbc or gcm')

    # create AES encrypt Cipher
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()

    # GCM mode
    if mode == 'gcm' and gcm_arg:
        with open(gcm_arg, 'rb') as f:
            additional_data = f.read()
        encryptor.authenticate_additional_data(additional_data)

    # encrypt data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # GCM mode add tag
    if mode == 'gcm':
        print("---------------encrypt----------")
        print(f"Ciphertext before adding tag: {ciphertext.hex()}")
        print(f"ciphertext Length before adding tag: {len(ciphertext)}")
        print(f"Tag: {encryptor.tag.hex()}")
        print(f"Tag Length: {len(encryptor.tag)}")
        ciphertext += encryptor.tag
        print(f"Final Ciphertext: {ciphertext.hex()}")
        print(f"Final ciphertext Length: {len(ciphertext)}")

    # output chipertext
    with open(ciphertext_file, 'wb') as f:
        f.write(ciphertext)


if __name__ == '__main__':
    # python aes-encrypt.py -key {key_file} -input {input_file} -out {output_file} -mode gcm -IV {IV_file} -gcm_arg {additional_file}
    parser = argparse.ArgumentParser(description="AES Encryption Script")
    parser.add_argument("-key", required=True, help="Key file path")
    parser.add_argument("-IV", required=False, help="IV file path (required for CBC and GCM)")
    parser.add_argument("-mode", required=True, choices=['ecb', 'cbc', 'gcm'], help="AES mode (ecb, cbc, or gcm)")
    parser.add_argument("-input", required=True, help="Plaintext input file path")
    parser.add_argument("-out", required=True, help="Ciphertext output file path")
    parser.add_argument("-gcm_arg", required=False, help="Additional authenticated data (AAD) file path for GCM")

    args = parser.parse_args()

    aes_encrypt(args.key, args.IV, args.mode, args.input, args.out, args.gcm_arg)