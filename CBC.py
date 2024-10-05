from Crypto.Cipher import AES
import random

def generate_IV():
    return bytes([random.randint(0, 255) for _ in range(16)])

def generate_key():
    return bytes([random.randint(0, 255) for _ in range(16)])

def submit(string):
    string.insert(0, "userid=456; userdata=")
    string.append(";session-id=31337")

def encrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) < 16:
            block += bytes([16 - len(block)]) * (16 - len(block))
        data = data[:i] + cipher.encrypt(block) + data[i+16:]
    return cipher.encrypt(data)


if __name__ == '__main__':
    with open('./plaintext.txt', 'rb') as f:
        plaintext = f.read()

    iv = generate_IV()
    key = generate_key()

    while iv == key:                                        # IV and key must be different
        iv = generate_IV()