from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
root = tk.Tk()
root.withdraw()  # hides the root window
root.update()


def getFileContents():
    file_path = filedialog.askopenfilename()
    with open(file_path, 'rb') as f:
        x = f.readlines()

    return x
# Generate private/public key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

public_key_bytes = public_key.public_bytes(  encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH)

private_key_bytes = private_key.private_bytes(  encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.OpenSSH, encryption_algorithm=serialization.NoEncryption())

with open("test.bin", 'wb') as f:
    f.write(public_key_bytes)

with open("test.bin", "rb") as f:
    public_key_bytes = f.read()

with open("test1.bin", 'wb') as f:
    f.write(private_key_bytes)

with open("test1.bin", "rb") as f:
    private_key_bytes = f.read()

public_key = serialization.load_ssh_public_key(
            public_key_bytes,
            backend=default_backend()
        )

private_key = serialization.load_ssh_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )

# Encrypt message with public key
message =  b"hello"
encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt message with private key
decrypted = private_key.decrypt(
    encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Print results
print("Encrypted message:", encrypted)

input_str = input("Enter byte string: ")
byte_str = bytes.fromhex(input_str)
print(byte_str)
# print(encrypted_)
print(encrypted)

#
# if encrypted_ == encrypted:
#     print("YAY")
#
# decrypted = private_key.decrypt(
#     encrypted_,
#     padding.OAEP(
#         mgf=padding.MGF1(algorithm=hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )
# print("Decrypted message:", decrypted)