from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json


def sign_in():
    k = 5
    while k > 0:
        username = input("\nEnter your username:").lower().strip()
        if os.path.exists(f"students_details/{username}.txt"):
            password = input("\nEnter your password:").encode()
            with open(f"students_details/{username}.txt", "r")as file:
                data= file.readlines()
                salt = bytes.fromhex(data[0].strip())
                stored_password_key = data[1].strip()
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend(),
                )
                input_password = base64.urlsafe_b64encode(kdf.derive(password))


            if input_password.hex() == stored_password_key:
                print("\nSigned in successfully")
                print(f"\nWelcome {username}")
                return username
            else:
                k -= 1
                if k > 0:
                    print(f"\nWrong username or password. You have {k} chances left")
                else:
                    print("\nNo chances left. Access Denied")                
        else:
            k -= 1
            if k > 0:
                print(f"\nWrong username or password. You have {k} chances left")
            else:
                print("\nNo chances left. Access Denied")
    return None


def result_checker(username):
    while True:
        print("\n1.View Result")
        print("2.Log out")
        try:
            choice = int(input("\nWhat do you want to do?(1/2):"))
            if choice not in range(1,3):
                raise ValueError
        except ValueError:
            print("\nError, Enter a valid command")
            continue
        if choice == 1:
            try:
                with open("results.json", "r") as f:
                    results = json.load(f)
            except:
                results = {}
            if username in results:
                user = results[username]
                print("-"*50)
                print(f"\nName: {user.get("Name") or "N/A"}")
                print(f"Roll no: {user.get("Roll no") or "N/A"}")
                print(f"Marks: {user.get("Marks") or "N/A"}")
                print("-"*50)
            else:
                print("\nYour result is not available.")
                continue

        elif choice == 2:
            print("\nLogged out")
            print("="*100)
            break


        
def student():
    print()
    print("-"*100)
    print("Student".center(100))
    print("-"*100)
    while True:
        print("\nLogin your account")
        username = sign_in()
        if username:
            result_checker(username)
            break
        else:
            break



