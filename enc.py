from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
import os

# Generate a random key for AES encryption
def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

# Encrypt a file
def encrypt_file(input_filename: str, password: str, output_filename: str = None):
    salt = os.urandom(16)
    key = generate_key(password.encode(), salt)
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(input_filename, 'rb') as f:
        data = f.read()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    if output_filename is None:
        output_filename = input_filename + ".enc"
        
    with open(output_filename, 'wb') as f:
        f.write(salt + iv + encrypted_data)
    
    print(f"File encrypted successfully! Encrypted file: {output_filename}")

# Decrypt a file
def decrypt_file(input_filename: str, password: str, output_filename: str = None):
    with open(input_filename, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()
    
    key = generate_key(password.encode(), salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    except InvalidKey:
        print("Invalid password or corrupted file.")
        return
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError:
        print("Invalid password or corrupted file.")
        return
    
    if output_filename is None:
        output_filename = input_filename.rsplit(".enc", 1)[0]
        
    with open(output_filename, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"File decrypted successfully! Decrypted file: {output_filename}")

if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", help="Encrypt the file", action="store_true")
    group.add_argument("-d", "--decrypt", help="Decrypt the file", action="store_true")
    parser.add_argument("file", help="File name")
    parser.add_argument("password", help="Password for encryption/decryption")
    parser.add_argument("-o", "--output", help="Output file name (optional)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"Error: The file '{args.file}' does not exist.")
        sys.exit(1)
    
    if args.encrypt:
        encrypt_file(args.file, args.password, args.output)
    elif args.decrypt:
        if not args.file.endswith(".enc"):
            print("Error: The file to be decrypted must have a .enc extension.")
            sys.exit(1)
        decrypt_file(args.file, args.password, args.output)