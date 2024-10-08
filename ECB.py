from Crypto.Cipher import AES
import random

def encrypt(key, data):
    header = data[:138]                                              # The first 138 bytes of the data are the header
    data = data[138:]
    padding_len = 16 - (len(data) % 16)
    data += bytes([padding_len] * padding_len)                                          # Pad the data before encryption
    
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = b''
    for i in range(0, len(data), 16):                               # Goes through 16 bytes of data at a time
        block = data[i:i+16]
        encrypted_data += cipher.encrypt(block)
    return header + encrypted_data

def decrypt(key, data):
    header = data[:138]
    data = data[138:]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = b''
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted_data += cipher.decrypt(block)
    padding_len = data[-1]
    decrypted_data[:-padding_len]                          # Unpad the data after decryption
    return header + decrypted_data

def generate_key():
    return bytes([random.randint(0, 255) for _ in range(16)])

if __name__ == '__main__':
    with open('./cp-logo.bmp', 'rb') as f:
        plaintext = f.read()

    key = generate_key()                                            # This key must be 16 bytes long
    ciphertext = encrypt(key, plaintext)

    with open('./ciphertext.bmp', 'wb') as f:
        f.write(ciphertext)

    with open('./ciphertext.bmp', 'rb') as f:
        ciphertext = f.read()
    
    decrypted = decrypt(key, ciphertext)
    with open('./decrypted.bmp', 'wb') as f:
        f.write(decrypted)