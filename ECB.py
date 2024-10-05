from Crypto.Cipher import AES
import random

def encrypt(key, data):
    header = data[:54]
    data = data[54:]
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), 16):                               # Goes through 16 bytes of data at a time
        block = data[i:i+16]
        if len(block) < 16:
            block += bytes([16 - len(block)]) * (16 - len(block))   # Pads the block with the number of bytes missing PKCS7
        data = data[:i] + cipher.encrypt(block) + data[i+16:]       # Appends the encrypted block to the data
    return header + cipher.encrypt(data)

def decrypt(key, data):
    header = data[:54]
    data = data[54:]
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        data = data[:i] + cipher.decrypt(block) + data[i+16:]
    return header + cipher.decrypt(data)

def generate_key():
    return bytes([random.randint(0, 255) for _ in range(16)])

if __name__ == '__main__':
    with open('./plaintext.txt', 'rb') as f:
        plaintext = f.read()

    key = generate_key()                                            # This key myst be 16 bytes long
    ciphertext = encrypt(key, plaintext)

    with open('./ciphertext.txt', 'wb') as f:
        f.write(ciphertext)

    with open('./ciphertext.txt', 'rb') as f:
        ciphertext = f.read()
    
    with open('./decrypted.txt', 'wb') as f:
        decrypted = decrypt(key, ciphertext)
        f.write(decrypted)