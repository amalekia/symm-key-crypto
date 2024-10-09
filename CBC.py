from Crypto.Cipher import AES
import os
import urllib.parse

key = None
iv = None
global_bytes_string = None

def generate_key():
    return os.urandom(16)

def generate_iv():
    return os.urandom(16)

def encrypt_data(key, iv, data, header_size=54):
    # we might want to change header_size to 138 depending
    bmp_header = data[:header_size] 
    # contains the rest of the plaintext data
    plaintext_data = data[header_size:]
    
    # Padding to ensure length of data is
    # multiple of 16 bytesm, otherwise adds it to the end
    padding_length = 16 - (len(plaintext_data) % 16)
    if padding_length != 0 and padding_length != 16:
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

def encrypt_data_P2(key, iv, data):
    # Padding to ensure length of data is
    # multiple of 16 bytesm, otherwise adds it to the end
    padding_length = 16 - (len(data) % 16)
    if padding_length != 0 and padding_length != 16:
        data += bytes([padding_length]) * padding_length
    
    # the actual cipher used for symmetric encryption
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    # will append the encrypted ciphers to this byte string
    # and then append this whole string to the output file
    ciphertext = b""
    
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block

    # we need to append the iv so that it can be used for decryption
    # steps later on
    return iv + ciphertext

def decrypt_data_P2(key, data):
    iv = data[:16] 
    encrypted_data = data[16:]
    
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
    
    return plaintext


def get_ciphertext_length(ciphertext):
    
    return len(ciphertext)

def flipping_bit_attack(ciphertext):
    # Find the index of 'admin%3D' in the global_bytes_string
    admin_index = global_bytes_string.find(b'admin%3D')
    if admin_index == -1:
        return ciphertext
    
    # Calculate the position in the ciphertext where we need to flip the bit
    block_size = 16
    block_index = admin_index // block_size
    byte_index_in_block = admin_index % block_size
    # Convert the ciphertext to a mutable bytearray
    modified_ciphertext = bytearray(ciphertext)
    # Flip the bit in the previous block to affect the current block's plaintext
    # We need to flip the bit in the byte before the 'admin%3D' string in the ciphertext
    modified_ciphertext[block_index * block_size + byte_index_in_block - block_size] ^= 1
    return bytes(modified_ciphertext)


def submit(string):
    # URL encode the string using quote function in urllib.parse
    string = "userid=456;userdata=" + urllib.parse.quote(string) + ";session-id=31337" 
    # Padding the string using PKCS#7
    block_size = 16
    padding_length = block_size - (len(string) % block_size)
    padded_string = string + chr(padding_length) * padding_length
    bytes_string = bytes(padded_string, 'utf-8')
    global global_bytes_string
    global_bytes_string = bytes_string
    return encrypt_data_P2(key, iv, bytes_string)

def verify(param):
    # Unpadding the string using PKCS#7
    padding_length = param[-1]
    param[:-padding_length]

    # Decrypt the string
    decrypted = decrypt_data_P2(key, param)
    print(f'Decrypted: {decrypted}')
    decrypted_str = decrypted.decode(errors='ignore')

    # Check if the string contains "admin=true"
    return "admin%3Dtrue" in decrypted_str

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
    with open('./cp-logo.bmp', 'rb') as f:
        plaintext = f.read()

    key = generate_key()                                            # This key myst be 16 bytes long
    iv = generate_iv()

    ciphertext = encrypt_data(key, iv, plaintext)

    with open('./ciphertext.bmp', 'wb') as f:
        f.write(ciphertext)

    with open('./ciphertext.bmp', 'rb') as f:
        ciphertext = f.read()
        
    
    with open('./decrypted.bmp', 'wb') as f:
        decrypted = decrypt_data(key, ciphertext)
        f.write(decrypted)
    
    # part 2
    with open('./plaintextP2.txt', 'rb') as f:
        plaintextP2 = f.read()
        ciphertext = submit(plaintextP2)
        print(type(ciphertext))
        print(f'Verifying if admin=true: {verify(ciphertext)}\n')
        # hacked_cipher_text is some bytes string
        hacked_cipher_text = flipping_bit_attack(ciphertext)
        print(type(hacked_cipher_text))
        print(f'Verifying if admin=true after flipping bit: {verify(hacked_cipher_text)}\n')