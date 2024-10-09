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
    res = None
    ciphertext_length = get_ciphertext_length(ciphertext)

    # Find 'admin=' in the global_bytes_string after decoding it
    adminIndex = global_bytes_string.find(b'admin%3D')

    # Convert bytestring to regular string
    regular_string = global_bytes_string.decode()
    regular_string = regular_string.replace('%3D', '=')

    # Find 'admin=' in the modified string
    adminIndex = regular_string.find('admin=')
    # Ciphertext length should be matching 
    if ciphertext_length > adminIndex:
        i = adminIndex + 6
        if regular_string[i] == 't':
            res = ciphertext
            print("Already true", res)
        elif regular_string[i] == 'f':
            # XOR the byte at index i to flip 'f' to 't'
            f_ascii = ord('f')
            t_ascii = ord('t')
            flip_mask = f_ascii ^ t_ascii  # XOR of 'f' and 't' gives the bit flip mask

            modified_ciphertext = bytearray(ciphertext)

            modified_ciphertext[adminIndex + 8] ^= flip_mask

            res = bytes(modified_ciphertext)
            print("\n\nAlready false, now is true\n", res)

    return res



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
    print("length of string in submit aftert padding is " , len(bytes_string))
    return encrypt_data_P2(key, iv, bytes_string)

def verify(param):
    print("verify string is " , param)
    # Unpadding the string using PKCS#7
    padding_length = param[-1]
    param[:-padding_length]

    # Decrypt the string
    decrypted = decrypt_data_P2(key, param)
    print(f'Decrypted: {decrypted}')
    decrypted_str = str(decrypted, 'utf-8')

    # Check if the string contains "admin=true"
    return "admin=true" in decrypted_str

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
        print("ciphertext " , ciphertext)
        print(f'Verifying if admin=true: {verify(ciphertext)}\n')
        # hacked_cipher_text is some bytes string
        hacked_cipher_text = flipping_bit_attack(ciphertext)
        print("hacked cipher text is " , hacked_cipher_text)
        print(f'Verifying if admin=true after flipping bit: {verify(hacked_cipher_text)}\n')