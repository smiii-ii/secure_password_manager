import bcrypt
import random

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def password_strength(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if any(c.isupper() for c in password):
        strength += 1
    if any(c.islower() for c in password):
        strength += 1
    if any(c.isdigit() for c in password):
        strength += 1
    if any(c in "!@#$%^&*()-_+=" for c in password):
        strength += 1
    return strength

def generate_recovery_phrase():
    words = ["apple", "sky", "yellow", "river", "mountain", "ocean",
             "star", "forest", "cloud", "tree"]
    return " ".join(random.sample(words, 4))
