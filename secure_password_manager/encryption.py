from cryptography.fernet import Fernet, InvalidToken
import os

# ----- Key Management -----

KEY_FILE = "secret.key"

def load_key():
    """Loads a Fernet key from file or generates a new one if absent."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

# Load Fernet key just once
KEY = load_key()
FERNET = Fernet(KEY)

# ----- Custom Symbol-Shift Encryption Layer -----

def custom_encrypt_password(plain_password: str) -> str:
    """Simple shift of alphabet, digits, special chars for obfuscation."""
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    digits = '0123456789'
    special_symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?/~`'
    encrypted_text = ''

    for c in plain_password:
        if c.lower() in alpha:
            idx = alpha.index(c.lower())
            new_idx = (idx + 1) % len(alpha)
            new_char = alpha[new_idx]
            encrypted_text += new_char.upper() if c.isupper() else new_char
        elif c in digits:
            idx = digits.index(c)
            new_idx = (idx + 1) % len(digits)
            encrypted_text += digits[new_idx]
        elif c in special_symbols:
            idx = special_symbols.index(c)
            new_idx = (idx + 3) % len(special_symbols)
            encrypted_text += special_symbols[new_idx]
        else:
            encrypted_text += c
    return encrypted_text

def custom_decrypt_password(enc_password: str) -> str:
    """Reverse the shift for alphabet, digits, special chars."""
    alpha = 'abcdefghijklmnopqrstuvwxyz'
    digits = '0123456789'
    special_symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?/~`'
    decrypted_text = ''

    for c in enc_password:
        if c.lower() in alpha:
            idx = alpha.index(c.lower())
            new_idx = (idx - 1) % len(alpha)
            new_char = alpha[new_idx]
            decrypted_text += new_char.upper() if c.isupper() else new_char
        elif c in digits:
            idx = digits.index(c)
            new_idx = (idx - 1) % len(digits)
            decrypted_text += digits[new_idx]
        elif c in special_symbols:
            idx = special_symbols.index(c)
            new_idx = (idx - 3) % len(special_symbols)
            decrypted_text += special_symbols[new_idx]
        else:
            decrypted_text += c
    return decrypted_text

# ----- Combined Encryption API -----

def encrypt_password(plain_password: str) -> str:
    """
    Encrypts the password for secure storage.
    Step 1: custom obfuscation
    Step 2: strong Fernet encryption
    Returns a base64-encoded ciphertext (string).
    """
    obscure_password = custom_encrypt_password(plain_password)
    return FERNET.encrypt(obscure_password.encode()).decode()

def decrypt_password(enc_password: str) -> str:
    """
    Decrypts the password, reverses custom obfuscation.
    Handles Fernet errors gracefully.
    """
    try:
        decrypted = FERNET.decrypt(enc_password.encode()).decode()
    except (InvalidToken, Exception):
        # If Fernet fails, return as is or empty string per your logic
        return ""
    return custom_decrypt_password(decrypted)

# ----- Usage Example -----

if __name__ == "__main__":
    pw = "Secret@123!"
    enc = encrypt_password(pw)
    print("Encrypted:", enc)
    dec = decrypt_password(enc)
    print("Decrypted:", dec)
