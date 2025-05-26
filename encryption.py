from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib


def hash(text: str):
    hashed = hashlib.sha256(text.encode()).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    return encoded.decode("utf-8")


def encrypt_secrets(username: str, password: str, text_to_encrypt=""):
    fernet = Fernet(hash(password))
    return fernet.encrypt(f"{username} {text_to_encrypt}".encode())


def decrypt_secrets(username: str, password: str, encrypted_text: str):
    try:
        fernet = Fernet(hash(password))
        decrypted = fernet.decrypt(encrypted_text).decode()
        segments = decrypted.split(" ")
        return segments[0] == username, segments[1:]
    except InvalidToken:
        return False, []


def encrypt(text: str, key: str):
    fernet = Fernet(hash(key))
    return fernet.encrypt(text.encode())


def decrypt(text: str, key: str):
    fernet = Fernet(hash(key))
    return fernet.decrypt(text).decode()
