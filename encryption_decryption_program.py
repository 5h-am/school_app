import decryption
import encryption

while True:
    print()
    print("="*100)
    print("Welcome to Encry/Decry Program".center(100))
    print("="*100)
    print("\n1.Encrypt a file")
    print("2.Decrypt a already encrypted file")
    print("3.Exit the Program")
    try:
        choice = int(input("\nWhat do you want to do(1/2/3):"))
        if choice not in range(1,4):
            raise ValueError
    except ValueError:
        print("Error, Enter a valid command")
        continue
    if choice == 1:
        result = encryption.encryption()
        if result is None:
            continue
    elif choice == 2:
        result = decryption.decryption()
        if result is None:
            continue
    elif choice == 3:
        print("\nGoodbye, Have a nice day\n")
        break
        


