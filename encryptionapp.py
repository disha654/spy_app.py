print("Welcome to Basic Encryption App")
choice = input("Type 'E' to encrypt or 'D' to decrypt: ").upper()
text = input("Enter your text: ")
shift = int(input("Enter shift key (number): "))

if choice == 'E':
    print("Encrypted Text:", encrypt(text, shift))
elif choice == 'D':
    print("Decrypted Text:", decrypt(text, shift))
else:
    print("Invalid choice!")