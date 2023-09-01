import tkinter as tk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# Generate a random salt for key derivation
def generate_salt():
    return os.urandom(16)

# Derive a key from a password and salt
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=1000000,  # Adjust the number of iterations for security
        salt=salt,
        length=48  # Length of the derived key
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Encrypt a message
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

# Decrypt a message
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# Create GUI
def create_gui():
    root = tk.Tk()
    root.title("Message Encoder & Decoder")

    password_label = tk.Label(root, text="Password:")
    password_label.pack()

    password_entry = tk.Entry(root, show="*")  # Show asterisks for password input
    password_entry.pack()

    message_label = tk.Label(root, text="Message:")
    message_label.pack()

    message_entry = tk.Entry(root)
    message_entry.pack()

    encrypted_label = tk.Label(root, text="Encrypted Message:")
    encrypted_label.pack()

    encrypted_message_label = tk.Label(root, text="")
    encrypted_message_label.pack()

    decrypted_label = tk.Label(root, text="Decrypted Message:")
    decrypted_label.pack()

    decrypted_message_label = tk.Label(root, text="")
    decrypted_message_label.pack()

    def encrypt():
        password = password_entry.get().encode()
        salt = generate_salt()
        key = derive_key(password, salt)
        message = message_entry.get()
        encrypted_message = encrypt_message(message, key)
        encrypted_message_label.config(text=encrypted_message)

    def decrypt():
        password = password_entry.get().encode()
        salt = generate_salt()
        key = derive_key(password, salt)
        encrypted_message = encrypted_message_label.cget("text")
        decrypted_message = decrypt_message(encrypted_message, key)
        decrypted_message_label.config(text=decrypted_message)

    encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
    encrypt_button.pack()

    decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
    decrypt_button.pack()

    root.mainloop()

if __name__ == "__main__":
    create_gui()
