import os
import time

import numpy
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad


def to_bin(data):
    # converting given data to their binary form
    if isinstance(data, str):
        return ''.join(format(i, '08b') for i in bytearray(data, encoding='utf-8'))
    elif isinstance(data, int) or isinstance(data, numpy.uint8):
        return format(data, '08b')
    elif isinstance(data, bytes) or isinstance(data, numpy.ndarray):
        return [format(i, '08b') for i in data]
    else:
        raise TypeError("Incorrect type!")

def to_ascii(binary_data):
    # converting binary data to ascii representation
    data_int = int(binary_data, 2)
    byte_nr = (data_int.bit_length() + 7) // 8
    data_bytes = data_int.to_bytes(byte_nr, 'big')
    data_ascii = data_bytes.decode(encoding='utf-8')
    return data_ascii

def get_data(image_path, password):
    # plaintext preparation
    image_file = open(image_path, 'rb')
    plaintext = image_file.read()
    image_file.close()

    # key preparation
    salt = b'An exemplary salt'             # additional security measure of a password
    key = PBKDF2(password, salt, 32, 1000)  # generating a key value from given password and salt of size 32 bytes through 1000 iterations
    return plaintext, key, image_path


def encrypt_CFB(plaintext, key):
    iv = key[:16]                           # get initialization vector
    cipher = AES.new(key, AES.MODE_CFB, iv)
    img_data = cipher.encrypt(plaintext)
    fname = 'encoded.png'
    with open(fname, 'wb') as f:
        f.write(img_data)
        f.close()
        return fname
    return False


def decrypt_CFB(cipher, password):
    with open(cipher, 'rb') as f:
        ciph = f.read()
        f.close()
    # Prepare data
    salt = b'An exemplary salt'    # additional security measure for a password
    key = PBKDF2(password, salt, 32, 1000)  # generating a key value from given password and salt of size 32 bytes through 1000 iterations
    iv = key[:16]                           # extracting iv from the last 16 bytes of key
    decipher = AES.new(key, AES.MODE_CFB, iv)
    try:
        recovered_data = decipher.decrypt(ciph)
    except ValueError:
        return False
    fname = 'decrypted.png'
    with open(fname, 'wb') as f:
        try:
            f.write(recovered_data)
        except ValueError:
            return False
        f.close()
        return fname


def encrypt_CBC(plaintext, key, im_path):
    iv = key[:16]  # random initialization vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    img_data = cipher.encrypt(pad(plaintext, 16))
    output_path = os.path.splitext(im_path)[0]
    extension = os.path.splitext(im_path)[1]
    fname = output_path + "_en_" + time.strftime("%d-%m-%Y-%H-%M-%S") + extension
    with open(fname, 'wb') as f:
        f.write(img_data)
        f.close()
        return fname
    return False


def decrypt_CBC(cipher, password):
    with open(cipher, 'rb') as f:
        ciph = f.read()
        f.close()
    # Prepare data
    salt = b'An exemplary salt'             # additional security measure of a password
    key = PBKDF2(password, salt, 32, 1000)  # generating a key value from given password and salt of size 32 bytes through 1000 iterations
    iv = key[:16]
    decipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        recovered_data = decipher.decrypt(ciph)
    except ValueError:
        return False
    output_path = os.path.splitext(cipher)[0]
    extension = os.path.splitext(cipher)[1]
    fname = output_path + "_decrypted_" + extension

    with open(fname, 'wb') as f:
        try:
            f.write(unpad(recovered_data, 16))
        except ValueError:
            return False
        f.close()
        return fname
    return False


def encrypt_text(plaintext, password):
    # key preparation
    salt = b'An exemplary salt'             # additional security measure of a password
    key = PBKDF2(password, salt, 32, 1000)  # generating a key value from given password and salt of size 32 bytes through 1000 iterations
    iv = key[:16]                           # initialization vector derived from a key
    cipher = AES.new(key, AES.MODE_CFB, iv)
    cryptogram = cipher.encrypt(plaintext)
    return cryptogram

def decrypt_text(cryptogram, password):
    # key preparation
    salt = b'An exemplary salt'             # additional security measure of a password
    key = PBKDF2(password, salt, 32, 1000)  # generating a key value from given password and salt of size 32 bytes through 1000 iterations
    iv = key[:16]                           # initialization vector derived from a key
    decipher = AES.new(key, AES.MODE_CFB, iv)
    print(type(cryptogram))
    print("szyfrogram: " + cryptogram)
#    cryptogram = str.encode(cryptogram)
   # print(type(cryptogram))
    try:
        cryptogram = str.encode(cryptogram, encoding="latin-1")
        print("Po konwersji "+ str(cryptogram))
        message = decipher.decrypt(cryptogram)
        print(type(message))
        print("plain: " + str(message))
    except ValueError:
        return False
    return message.decode('latin-1')

