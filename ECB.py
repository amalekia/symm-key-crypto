from Crypto.Cipher import AES
import random

def encrypt(key, data):
    header = data[:138]                                              # The first 54 bytes of the data are the header
    data = data[138:]
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), 16):                               # Goes through 16 bytes of data at a time
        block = data[i:i+16]
        if len(block) < 16:
            block += bytes([16 - len(block)]) * (16 - len(block))   # Pads the block with the number of bytes missing PKCS7
        data = data[:i] + cipher.encrypt(block) + data[i+16:]       
    return header + cipher.encrypt(data)

def decrypt(key, data):
    header = data[:138]
    data = data[138:]
    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        data = data[:i] + cipher.decrypt(block) + data[i+16:]
    data = header + cipher.decrypt(data)
    padding_len = data[-1]                                          # Gets the padding length
    return data[:-padding_len]                                      # Removes the padding

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