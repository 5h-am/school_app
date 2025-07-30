from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.fernet import Fernet, InvalidToken
import os


def encrypt_file_name():
    encrypt_file = input("\nEnter the encrypted file name you want to decrypt:")
    encrypt_file += ".enc"
    if os.path.exists(encrypt_file):
        return encrypt_file
    else:
        print(f"\nError, {encrypt_file} not found")
        return None
    
def decryption_file():
    while True:
        decrypt_file = input("\nSet the name of your decrypted file:")
        if not decrypt_file:
            print("\nError, You can't leave the file name empty")
            continue
        else:
            decrypt_file += ".dec"
            if os.path.exists(decrypt_file):
                print(f"\nError, {decrypt_file} already exists")
                continue
            else:
                return decrypt_file
        
def use_password(salt):
    password = input("\nEnter password to decrypt:").encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)
    

def decryption():
    ef = encrypt_file_name()
    if ef is not None:
        with open(ef, "rb") as f:
            salt = f.read(16)
            encrypted = f.read()
    else:
        return None
    df = decryption_file()
    cipher = use_password(salt)
    if cipher is None:
        return None
    try:
        decrypted = cipher.decrypt(encrypted)
        with open(df, "wb") as f:
            f.write(decrypted)
            print(f"\nFile decrypted successfully and saved as {df}")
    except InvalidToken:
        print("\nDecryption failed, Wrong Password")
        return None







