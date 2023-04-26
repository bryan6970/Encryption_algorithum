import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter import filedialog

root = tk.Tk()
root.withdraw()  # hides the root window
root.update()


def getFileContents():
    file_path = filedialog.askopenfilename()
    with open(file_path, 'rb') as f:
        x = f.read()

    print(x)

    return x

def getPrivateKeyObj():
    file_path = filedialog.askopenfilename()

    with open(file_path, "rb") as f:
        private_key_bytes = f.read()

    private_key = serialization.load_ssh_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key

def decryptMessage(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


print("Select the file with your key")
key_obj = getPrivateKeyObj()

response = input("Is your message in a file or in text?\n")
if response.upper() == "FILE":
    print("You may have to press alt tab to see the file")
    encrypted_message = getFileContents()
else:
    encrypted_message = bytes.fromhex(input("Message\n"))


try:
    decrypted_message = decryptMessage(key_obj, encrypted_message)
except ValueError:
    raise ValueError("Corrupted encrypted message or wrong encryption key")

if input(f"Your decrypted message is {decrypted_message}\nDo you want to save it to a file?").upper() == "YES":
    print("You may have to press alt tab to save the file")
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    with open(file_path, 'wb') as f:
        f.write(decrypted_message)



