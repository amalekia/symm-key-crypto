from Crypto.Cipher import AES
import random

def generate_IV():
    return bytes([random.randint(0, 255) for _ in range(16)])

def generate_key():
    return bytes([random.randint(0, 255) for _ in range(16)])


if __name__ == '__main__':
    with open('./plaintext.txt', 'rb') as f:
        plaintext = f.read()

    iv = generate_IV()
    key = generate_key()

    while iv == key:                                        # IV and key must be different
        iv = generate_IV()