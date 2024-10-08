from Crypto.Cipher import AES
import os
import urllib.parse

def generate_key():
    return os.urandom(16)

def generate_iv():
    return os.urandom(16)

def submit(string):
    # URL encode the string using quote function in urllib.parse
    string = "userid=456;userdata=" + urllib.parse.quote(string) + ";session-id=31337" 
    # Padding the string using PKCS#7
    block_size = 16
    padding_length = block_size - (len(string) % block_size)
    padded_string = string + chr(padding_length) * padding_length
    return padded_string

def verify(string):
    # Unpadding the string using PKCS#7
    padding_length = string[-1]
    return string[:-padding_length]


def encrypt_data(key, iv, data, header_size=54):
    # we might want to change header_size to 138 depending
    bmp_header = data[:header_size] 
    # contains the rest of the plaintext data
    plaintext_data = data[header_size:]
    
    # Padding to ensure length of data is
    # multiple of 16 bytesm, otherwise adds it to the end
    padding_length = 16 - (len(plaintext_data) % 16)
    plaintext_data += bytes([padding_length]) * padding_length
    
    # the actual cipher used for symmetric encryption
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # will append the encrypted ciphers to this byte string
    # and then append this whole string to the output file
    ciphertext = b""
    
    for i in range(0, len(data), 16):
        block = plaintext_data[i:i+16]
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block

    # we need to append the iv so that it can be used for decryption
    # steps later on
    return bmp_header + iv + ciphertext

def decrypt_data(key, data, header_size=54):
    bmp_header = data[:header_size]
    # get the iv that we prepended in the encryption steps
    iv = data[header_size:header_size + 16] 
    encrypted_data = data[header_size + 16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # creating a plaintext string
    plaintext_padded = b""
    
    # looping through 16 byte intervals since we know
    # this data is already padded properly
    for i in range(0, len(data), 16):
        block = encrypted_data[i:i+16]
        decrypted_block = cipher.decrypt(block)
        plaintext_padded += decrypted_block

    #Unpadding
    padding_length = plaintext_padded[-1]
    plaintext = plaintext_padded[:-padding_length]
    
    return bmp_header + plaintext

if __name__ == '__main__':
    # part 1
    with open('./plaintext.txt', 'rb') as f:
        plaintext = f.read()

    key = generate_key()                                            # This key myst be 16 bytes long
    iv = generate_iv()

    ciphertext = encrypt_data(key, iv, plaintext)

    with open('./ciphertext.txt', 'wb') as f:
        f.write(ciphertext)

    with open('./ciphertext.txt', 'rb') as f:
        ciphertext = f.read()
    
    with open('./decrypted.txt', 'wb') as f:
        decrypted = decrypt_data(key, ciphertext)
        f.write(decrypted)
    
    # part 2
    with open('./plaintextP2.txt', 'rb') as f:
        plaintextP2 = f.read()
        print(f'Original plaintext: {plaintextP2}')
        ciphertext = submit(plaintextP2)
        print(f'Generated ciphertext: {ciphertext}')
        # print(f'Verifying if admin=true: {verify(ciphertext)})')