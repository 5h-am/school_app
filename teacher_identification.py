from check_admin_password import admin_check
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json


def set_password():
    while True:
        password = input("\nSet the password:")
        if not password:
            print("\nError, You can't leave the password empty")
            continue
        else:
            confirm = input("Confirm the password:")
            if confirm == password:
                print("\nPassword has been set")
                return confirm.encode()
            else:
                print("\nBoth passwords are different")
                continue

def sign_up():
    access = admin_check()
    if access:
        while True:
            username = input("\nSet your username:").lower().strip()
            if not username:
                print("\nError, You can't leave the username empty")
                continue
            elif os.path.exists(f"teachers_details/{username}.txt"):
                print("\nUsername already exists")
                continue
            else:
                password = set_password()
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend(),
                )
                password_key = base64.urlsafe_b64encode(kdf.derive(password)) 
                with open (f"teachers_details/{username}.txt", "w") as f:
                    f.write(salt.hex())
                    f.write("\n")
                    f.write(password_key.hex())
                    print("\nNew Teacher Account created")
                    return True
    else:
        return False
            

def sign_in():
    k = 5
    while k > 0:
        username = input("\nEnter your username:").lower().strip()
        if os.path.exists(f"teachers_details/{username}.txt"):
            password = input("\nEnter your password:").encode()
            with open(f"teachers_details/{username}.txt", "r")as file:
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
                return True
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
    return False
        


def student_register():
    while True:
        username = input("Set student's username:").lower().strip()
        if not username:
            print("Error, You can't leave the username empty")
            continue
        elif os.path.exists(f"students_details/{username}.txt"):
            print("Username already exists")
            continue
        else:
            password = set_password()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            password_key = base64.urlsafe_b64encode(kdf.derive(password)) 
            with open (f"students_details/{username}.txt", "w") as f:
                f.write(salt.hex())
                f.write("\n")
                f.write(password_key.hex())
                print("Student Registered")
                break
    
def update_result():
    username = input("\nEnter student's username:").lower().strip()
    if os.path.exists(f"students_details/{username}.txt"):
        name = input("\nEnter student's name:").title()
        roll_no = int(input("Enter student's roll no:"))
        marks = float(input("Enter student's mark:"))
        if os.path.exists("results.json") and os.path.getsize("results.json") > 0:
            with open("results.json", "r") as f:
                try:
                    results = json.load(f)
                except json.JSONDecodeError:
                    results = {}
            results[username] = {
                                "Name": name,
                                "Roll no": roll_no,
                                "Marks": marks
                                }
        else:
            results = {}
        with open("results.json", "w") as f:
            json.dump(results, f, indent=4)
        print(f"The result of {username} is saved")
    else:
        print("No student with this username was found")
    

def work():
    while True:
        print("\n1.Register a student")
        print("2.Add Result of a student")
        print("3.Log out")
        try:
            choice = int(input("\nWhat do you want to do?(1/2/3):"))
            if choice not in range(1,4):
                raise ValueError
        except ValueError:
            print("\nError, Enter a valid command")
            continue
        if choice == 1:
            student_register()
        elif choice == 2:
            update_result()
        elif choice == 3:
            print("\nLogged Out")
            print("="*100)
            break
        
def teacher():
    print()
    print("-"*100)
    print("Teacher".center(100))
    print("-"*100)
    while True:
        print("\n1.Login your account")
        print("2.Create a new account")
        print('3.Exit the program')
        try:
            action = int(input("\nWhat do you want to do?(1/2/3):"))
            if action not in range(1,4):
                raise ValueError
        except ValueError:
            print("\nError, Enter a valid command")
            continue
        if action == 1:
            result = sign_in()
            if result:
                work()
                continue
            else:
                break
        elif action == 2:
            result = sign_up()
            if result:
                continue
            else:
                break
        elif action == 3:
            print("="*100)
            break