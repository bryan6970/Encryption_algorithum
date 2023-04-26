import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter import filedialog

root = tk.Tk()
root.withdraw() # hides the root window


def getFileContents():
    file_path = filedialog.askopenfilename()
    with open(file_path, 'rb') as f:
        x = f.read()

    return x

def saveIntoFile():
    file_path = filedialog.asksaveasfilename(defaultextension=".bin")
    with open(file_path, 'wb') as f:
        f.truncate(0)
        f.write(encrypted_message)

def getPublicKeyObj():
    file_path = filedialog.askopenfilename()

    with open(file_path, "rb") as f:
        public_key_bytes = f.read()

    public_key = serialization.load_ssh_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    return public_key

def encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

print("Select the file with your key")
key_obj = getPublicKeyObj()

response = input("Is your message in a file or in text?\n")
if response.upper() == "FILE":
    print("You may have to press alt tab to see the file")
    message = getFileContents()
else:
    message = input("Message\n").encode()

encrypted_message = encrypt_message(key_obj, message)



if input(f"Your encrypted hex message is {binascii.hexlify(encrypted_message)}\nDo you want to save it to a file?").upper() == "YES":
    print("You may have to press alt tab to save the file")
    saveIntoFile()



