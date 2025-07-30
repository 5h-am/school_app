from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

def admin_check():
    k = 3
    while k > 0:
        password = input("\nEnter Admin password:").encode()
        with open("admin_key.txt","r") as f:
            salt = bytes.fromhex(f.readline().strip())
            stored_key = f.readline().strip()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
        user_key = base64.urlsafe_b64encode(kdf.derive(password))
        if user_key.hex() == stored_key:
            print("\nPassword is right")
            print("\nYou can now enjoy admin priviliges")
            return True

        else:
            print("\nPassword is wrong")
            k -= 1
            if k > 0:
                print(f"\nYou have {k} chances left")
            else:
                print("\nNo Attempts left. Access Denied\n")
    return False

    
    
