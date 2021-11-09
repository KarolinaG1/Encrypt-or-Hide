import math
import os.path
import time
from math import log10, sqrt

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


def to_ascii(binary_data):
    # converting binary data to their ascii representation
    data_int = int(binary_data, 2)
    byte_nr = (data_int.bit_length() + 7) // 8
    data_bytes = data_int.to_bytes(byte_nr, 'big')
    data_ascii = data_bytes.decode(encoding='utf-8')
    return data_ascii


def get_data(image_path, secret):
    image = cv2.imread(image_path)
    if image is not None:
        max_secret_length = image.shape[0] * image.shape[1] * 3 // 8  # in bytes
        secret_length = len(secret.encode('utf-8'))

        if secret_length > max_secret_length:
            print("You can't hide such message in this picture - it's too long")
            return 111, False, 0, 100
        else:
            print("You can hide this message. Performing steganography...")
            bit_loss, output_path = hide_message(image, secret, image_path, None)
            # MSE and PSNR calculation
            cover_im = cv2.imread(image_path)
            stego_im = cv2.imread(output_path)
            mse, psnr = MSE_PSNR(cover_im, stego_im)
            print("MSE: " + str(mse))
            print("PSNR: " + str(psnr))
            return bit_loss, output_path, mse, psnr
    else:
        return 111, False, 0, 100


def get_data_f(cover_image, secret_file):
    cover = cv2.imread(cover_image)
    secret = open(secret_file, "rb")
    file_extension = os.path.splitext(secret_file)[1]
    if cover is not None and secret is not None:
        secret = to_bin(secret.read())
        secret_bin = ''.join(secret)
        file_ex_bin = to_bin(file_extension)
        cover_capacity = (cover.shape[0] * cover.shape[1] * 3) - len(to_bin("@#@#@")) - len(to_bin(len(secret_bin))) \
                         - len(to_bin("$$$$$")) - len(file_ex_bin)
        print("Len of file ex: " + str(len(file_ex_bin)))
        if cover_capacity >= len(secret_bin):
            print("You can hide this file in a chosen cover image. Performing steganography...")
            bit_loss, output_path = hide_message(cover, secret_bin, cover_image, file_ex_bin)
            cover_im = cv2.imread(cover_image)
            stego_im = cv2.imread(output_path)
            mse, psnr = MSE_PSNR(cover_im, stego_im)
            print("MSE: " + str(mse))
            print("PSNR: " + str(psnr))
            return bit_loss, output_path, mse, psnr
        else:
            print("You can't hide this file in a chosen cover image.")
            return 111, False, 0, 100


def MSE_PSNR(cover_file, stego_file):
    # calculation of Mean Squared Error and Peak Signal to Noise Ratio
    mse = numpy.mean((cover_file - stego_file) ** 2)
    if mse == 0:
        return 0, 100
    max_pixel_intensity = 255.0
    psnr = 20 * log10(max_pixel_intensity / sqrt(mse))
    return mse, psnr


def calculate_capacity(image_path):
    cover_image = cv2.imread(image_path)
    # get number of bits the image consists of
    image_full_capacity = cover_image.shape[0] * cover_image.shape[1] * 3
    # secret text capacity calculation
    image_cap = image_full_capacity - len(to_bin("@#@#@"))
    length = 0
    msg = image_cap
    while (len(to_bin(image_cap))) > length:
        length += 1
        msg -= 1
    capacity_ascii = msg // 16  # worst-case scenario -- all-polish-characters
    capacity_ascii = math.floor(capacity_ascii)
    # secret file capacity calculation
    image_cap = image_cap - len(to_bin("$$$$$")) - 40   # worst-case scenario -- file extension of 5 characters length
    length = 0
    msg = image_cap
    while (len(to_bin(image_cap))) > length:
        length += 1
        msg -= 1
    capacity_file = msg // 8    # bin-to-byte conversion

    return capacity_ascii, capacity_file


def hide_message(image, secret, original_path, file_extension):
    # secret message preparation
    if file_extension is not None:
        secret_bin = secret
        secret_bin_len = len(secret_bin)
        secret_bin = bin(secret_bin_len)[2:] + to_bin("@#@#@") + secret_bin + file_extension + to_bin("$$$$$")
        secret_bin_len = len(secret_bin)
    else:
        secret_bin = to_bin(secret)
        secret_bin_len = len(secret_bin)
        secret_bin = bin(secret_bin_len)[2:] + to_bin("@#@#@") + secret_bin
        secret_bin_len = len(secret_bin)

    height, width = image.shape[0], image.shape[1]
    capacity = height * width * 3
    bit_pointer = 0

    for i in range(height):
        for j in range(width):
            # changing values of LSB in each RGB channel to a secret message
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

    output_path = os.path.dirname(original_path)
    extension = os.path.splitext(original_path)[1]
    output_path = output_path + "/secret_" + time.strftime("%d-%m-%Y-%H-%M-%S") + extension
    cv2.imwrite(output_path, image)
    # calculating percentage of data loss as bits of the image that need to be modified to store the message
    loss_percentage = (secret_bin_len / capacity) * 100
    return loss_percentage, output_path


def uncover_message(image_path):
    image = cv2.imread(image_path)
    if image is not None:
        height, width = image.shape[0], image.shape[1]
        lsb_all = ''
        # Extracting all LSBs of the cover image to one variable
        for i in range(height):
            for j in range(width):
                pixel = image[i, j]
                from_r = to_bin(pixel[0])
                from_g = to_bin(pixel[1])
                from_b = to_bin(pixel[2])
                lsb_all += from_r[7] + from_g[7] + from_b[7]

        # Extracting the bits of the message from collected LSBs
        delimiter = to_bin("@#@#@")
        end_of_msg_len = lsb_all.find(delimiter)
        if end_of_msg_len != -1:
            msg_len_bin = lsb_all[0:end_of_msg_len]
            msg_len = int(msg_len_bin, 2)
            start_of_msg_pointer = end_of_msg_len + len(delimiter)
            end_of_msg_pointer = start_of_msg_pointer + msg_len
            message = lsb_all[start_of_msg_pointer:end_of_msg_pointer]
            try:
                uncovered_message = to_ascii(message)
            except Exception:
                return False
            return uncovered_message
        else:
            return False
    else:
        return False


def uncover_file(image_path):
    image = cv2.imread(image_path)
    if image is not None:
        height, width = image.shape[0], image.shape[1]
        lsb_all = ''
        # Extracting all LSBs of the cover image to one variable
        for i in range(height):
            for j in range(width):
                pixel = image[i, j]
                from_r = to_bin(pixel[0])
                from_g = to_bin(pixel[1])
                from_b = to_bin(pixel[2])
                lsb_all += from_r[7] + from_g[7] + from_b[7]

        # Extracting the bits of the secret file from collected LSBs
        delimiter = to_bin("@#@#@")
        delimiter2 = to_bin("$$$$$")
        end_of_msg_len = lsb_all.find(delimiter)
        end_of_ext_len = lsb_all.find(delimiter2)
        if end_of_msg_len != -1:
            msg_len_bin = lsb_all[0:end_of_msg_len]
            msg_len = int(msg_len_bin, 2)
            start_of_msg_pointer = end_of_msg_len + len(delimiter)
            end_of_msg_pointer = start_of_msg_pointer + msg_len
            message = lsb_all[start_of_msg_pointer:end_of_msg_pointer]
            extension = lsb_all[end_of_msg_pointer:end_of_ext_len]
            output_path = os.path.dirname(image_path)
            try:
                fname = output_path + "/uncovered_" + time.strftime("%d-%m-%Y-%H-%M-%S") + to_ascii(extension)
            except UnicodeDecodeError:
                return False
            message = str.encode(message)
            message = int(message, 2).to_bytes((len(message) + 7) // 8, 'big')
            with open(fname, 'wb') as f:
                try:
                    f.write(message)
                except ValueError:
                    return False
                f.close()
                return fname.split("/")[-1]
        else:
            return False
    else:
        return False
