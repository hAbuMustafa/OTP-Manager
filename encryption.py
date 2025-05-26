from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib


def pw_hash(password):
    hashed = hashlib.sha256(password.encode()).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    return encoded.decode("utf-8")


def encrypt(username, password, text_to_encrypt=""):
    fernet = Fernet(pw_hash(password))
    return fernet.encrypt(f"{username} {text_to_encrypt}".encode())


def decrypt(username, password, encrypted_text):
    try:
        fernet = Fernet(pw_hash(password))
        decrypted = fernet.decrypt(encrypted_text).decode()
        segments = decrypted.split(" ")
        return segments[0] == username, segments[1:]
    except InvalidToken:
        return False, []
