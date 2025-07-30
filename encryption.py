from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

def file():
    try:
        f = input("\nEnter the file name(if it is in the same folder) or path you want to encrypt:")
        if not os.path.exists(f):
            raise ValueError
    except ValueError:
        return None
    return f

def set_password():
    while True:
        password = input("\nSet the password:")
        if not password:
            print("\nError, You can't leave the password empty")
            continue
        else:
            confirm = input("Confirm the password:")
            if confirm != password:
                print("\nPasswords doesn't match")
                continue
            else:
                print("\nPassword set.")
                return confirm.encode()
        
def encryption_file():
    while True: 
        file_name = input("Set the file name for encrypted data:")
        if not file_name:
            print("\nError, You can't leave a file name empty")
            continue
        else:
            file_name += ".enc"
            if os.path.exists(file_name):
                print(f"\nError, {file_name} already exists.")
                continue
            else:
                return file_name

def key_generation(salt):
    password = set_password()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encryption():
    fl = file()   
    if fl is None:
        print("\nError, Please enter a valid path")
        return None
    try:
        with open(fl,"rb") as f:
            message = f.read()
    except Exception as e:
        print(f"\nError reading file: {e}") 
        return None
    encrypted_file = encryption_file()
    salt = os.urandom(16)
    cipher = Fernet(key_generation(salt))
    encrypted = cipher.encrypt(message)
    with open(encrypted_file,"wb") as f:
        f.write(salt)
        f.write(encrypted)
    print(f"\nEncrypted file saved as {encrypted_file}")
            


