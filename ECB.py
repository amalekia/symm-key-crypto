from Crypto.Cipher import AES

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


if __name__ == '__main__':
    