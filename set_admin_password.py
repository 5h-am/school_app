from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os


def set_admin_password():
    while True:
        password = input("\nEnter the password:")
        if not password :
            print("\nYou can't leave the password empty")
            continue
        else:
            confirm = input("\nConfirm the password:")
            if password == confirm:
                print("\nPassword has been set")
                return password.encode()
            else:
                print("\nBoth Passwords are different")
                continue
            
def admin_key_making():
    admin_password = set_admin_password()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(admin_password))    
    with open("admin_key.txt","w") as f:
        f.write(salt.hex())
        f.write("\n")
        f.write(key.hex())



            
        


