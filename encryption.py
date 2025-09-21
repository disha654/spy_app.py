def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shifted = chr((ord(char.upper()) - 65 + shift) % 26 + 65)
            result += shifted
        else:
            result += char  
    return result

def decrypt(text, shift):
    return encrypt(text, -shift) 

# Test
plain_text = "Agent X will rendezvous at the secret lab"
shift = 3

encrypted_text = encrypt(plain_text, shift)
print("Encrypted:", encrypted_text)

decrypted_text = decrypt(encrypted_text, shift)
print("Decrypted:", decrypted_text)
