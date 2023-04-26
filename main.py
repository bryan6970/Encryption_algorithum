from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

with open("private_key.pem", "wb") as f:
    f.truncate(0)
    f.write(private_key_bytes)

with open("public_key.pem", "wb") as f:
    f.truncate(0)
    f.write(public_key_bytes)
