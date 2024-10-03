from Crypto.Cipher import AES
import random

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) < 16:
            block += b'\x00' * (16 - len(block))                # Padding with null bytes
        data = data[:i] + cipher.encrypt(block) + data[i+16:]
    return cipher.encrypt(data)

def generate_key():
    return bytes([random.randint(0, 255) for _ in range(16)])

if __name__ == '__main__':
    with open('/path/to/your/inputfile', 'rb') as f:
        plaintext = f.read()

    key = generate_key()                                  # This key myst be 16 bytes long
    ciphertext = encrypt(key, plaintext)

    with open('/path/to/your/outputfile', 'wb') as f:
        f.write(ciphertext)