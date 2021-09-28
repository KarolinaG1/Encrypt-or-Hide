# -*- coding: utf-8 -*-
import codecs
import os.path
import time

import cv2
import numpy


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


'''
def to_ascii(binary_data):
    #converting binary data to ascii representation
    data_int = int(binary_data, 2)
    byte_nr = data_int.bit_length() + 7 // 8
    #lsb_bytes = [lsb_all[i:i+8] for i in range(0, len(lsb_all), 8)]
    #print(lsb_bytes)
    data_bytes = data_int.to_bytes(byte_nr, "big")
    data_ascii = data_bytes.decode(encoding='utf-8', errors='ignore')
    return data_ascii
'''


def to_ascii(binary_data):
    # converting binary data to ascii representation
    ascii_data = []
    for i in range(int((len(binary_data) + 1) / 8)):
        ascii_data.append(binary_data[i * 8:(i * 8 + 8)])
    ascii_data = [chr(int(''.join(i), 2)) for i in ascii_data]
    ascii_data = ''.join(ascii_data)
    return ascii_data


def get_data(image_path, secret):
    image = cv2.imread(image_path)
    if image is not None:
        max_secret_length = image.shape[0] * image.shape[1] * 3 // 8  # in bytes
        print("You can hide a secret of " + str(max_secret_length) + " bits length in this picture.")
        secret_length = len(secret.encode('utf-8'))
        print("The secret's length is: " + str(secret_length) + " bytes")

        if secret_length > max_secret_length:
            print("You can't hide such message in this picture - it's too long")
            bit_loss = None
        else:
            print("You can hide this message. Performing steganography...")
            bit_loss, output_path = hide_message(image, secret, image_path)
        return bit_loss, output_path
    else:
        return 111, False


def hide_message(image, secret, original_path):
    # secret message preparation
    secret_bin = to_bin(secret)
    print("Secret message to be hidden in binary form: " + secret_bin)
    secret_bin_len = len(secret_bin)
    print("Length of the message in bits: " + str(secret_bin_len))
    secret_bin = bin(secret_bin_len)[2:] + to_bin("@#@#@") + secret_bin
    print("Message with overload added: " + secret_bin)
    secret_bin_len = len(secret_bin)
    print("Length of the final secret: " + str(secret_bin_len))

    height, width = image.shape[0], image.shape[1]
    capacity = height * width * 3
    bit_pointer = 0

    for i in range(height):
        for j in range(width):
            # changing values of LSB in each RGB channel to secret message
            # (if there's still data to be hidden)
            pixel = image[i, j]
            if bit_pointer < secret_bin_len:
                red = to_bin(pixel[0])
                modified_red = red[:-1] + secret_bin[bit_pointer]
                pixel[0] = int(modified_red, 2)
                bit_pointer += 1
            if bit_pointer < secret_bin_len:
                green = to_bin(pixel[1])
                modified_green = green[:-1] + secret_bin[bit_pointer]
                pixel[1] = int(modified_green, 2)
                bit_pointer += 1
            if bit_pointer < secret_bin_len:
                blue = to_bin(pixel[2])
                modified_blue = blue[:-1] + secret_bin[bit_pointer]
                pixel[2] = int(modified_blue, 2)
                bit_pointer += 1
            if bit_pointer >= secret_bin_len:
                break

    output_path = os.path.splitext(original_path)[0]
    extension = os.path.splitext(original_path)[1]
    output_path = output_path + "_secret_" + time.strftime("%d-%m-%Y-%H-%M-%S") + extension
    cv2.imwrite(output_path, image)
    # calculating percentage of data loss as bits of the image that need to be modified to store the message
    loss_percentage = (secret_bin_len / capacity) * 100
    return loss_percentage, output_path


def recover_message(image_path):
    image = cv2.imread(image_path)
    if image is not None:
        height, width = image.shape[0], image.shape[1]
        lsb_all = ''

        for i in range(height):
            for j in range(width):
                pixel = image[i, j]
                from_r = to_bin(pixel[0])
                from_g = to_bin(pixel[1])
                from_b = to_bin(pixel[2])
                lsb_all += from_r[7] + from_g[7] + from_b[7]

        delimiter = to_bin("@#@#@")
        end_of_msg_len = lsb_all.find(delimiter)
        if end_of_msg_len != -1:
            print(end_of_msg_len)
            # print(end_of_msg_len)
            msg_len_bin = lsb_all[0:end_of_msg_len]
            # print(msg_len_bin)
            msg_len = int(msg_len_bin, 2)
            print("Length of the recovered message: " + str(msg_len))
            start_of_msg_pointer = end_of_msg_len + len(delimiter)
            end_of_msg_pointer = start_of_msg_pointer + msg_len
            message = lsb_all[start_of_msg_pointer:end_of_msg_pointer]
            recovered_message = to_ascii(message)
            # recovered_message = (''.join([chr(int(x,2)) for x in re.split('(........)', message) if x ])).encode('utf-8').decode('utf-8')
           # print("Message in ascii representation: " + recovered_message)
            r_m = recovered_message.encode('utf-8')
            r_m = codecs.decode(r_m, 'utf-8')
            #print("Message in ascii representation (v2): " + r_m)
            return recovered_message
        else:
            return False
    else:
        return False
    # msg_len_int = int()
    # recovered_ascii = ''.join(chr(int(lsb_all[i:i+8],2)) for i in range(len(lsb_all))[::8])
    # f = open("C://Users//User//Desktop//secret.txt", "w", encoding="utf-8")
    # f.write(recovered_message)
    # print(f.read())
    # f.close()
    # recovered = ''.join(chr(int(char, 2)))
    # recovered = int(lsb_all, 2)
    # recovered = recovered.to_bytes((recovered.bit_length() + 7) // 8, 'big').decode(encoding='utf-8', errors='ignore')
    # print(recovered)



