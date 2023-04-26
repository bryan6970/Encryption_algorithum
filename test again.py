
with open("test.txt", 'rb') as f:
    encrypted_message_hex = f.read().hex()

print(encrypted_message_hex)
encrypted_message = bytes.fromhex(encrypted_message_hex)
print(encrypted_message)

user_input = hex(input("Paste the contents here: "))
user_input_bytes = bytes.fromhex(user_input)

if user_input_bytes == encrypted_message:
    print("Contents match.")
else:
    print("Contents do not match.")
