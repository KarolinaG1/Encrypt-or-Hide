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
    # converting binary data to ascii representation
    data_int = int(binary_data, 2)
    byte_nr = (data_int.bit_length() + 7) // 8
    data_bytes = data_int.to_bytes(byte_nr, 'big')
    data_ascii = data_bytes.decode(encoding='utf-8')
    return data_ascii


def get_data(image_path, secret):
    image = cv2.imread(image_path)
    if image is not None:
        max_secret_length = image.shape[0] * image.shape[1] * 3 // 8  # in bytes
        print("You can hide a secret of " + str(max_secret_length) + " bits length in this picture.")
        secret_length = len(secret.encode('utf-8'))
        print("The secret's length is: " + str(secret_length) + " bytes")

        if secret_length > max_secret_length:
            print("You can't hide such message in this picture - it's too long")
            return 111, False, 0, 100
        else:
            print("You can hide this message. Performing steganography...")
            bit_loss, output_path = hide_message(image, secret, image_path)
            # MSE and PSNR calculation
            cover_im = cv2.imread(image_path)
            stego_im = cv2.imread(output_path)
            mse, psnr = MSE_PSNR(cover_im, stego_im)
            print("MSE: " + str(mse))
            print("PSNR: " + str(psnr))
            return bit_loss, output_path, mse, psnr
    else:
        return 111, False, 0, 100


def MSE_PSNR(cover_file, stego_file):
    # calculation of Mean Squared Error
    mse = numpy.mean((cover_file - stego_file) ** 2)
    if mse == 0:
        return 0, 100
    max_pixel_intensity = 255.0
    psnr = 20 * log10(max_pixel_intensity/sqrt(mse))
    return mse, psnr


def hide_message(image, secret, original_path):
    # secret message preparation
    print(type(secret))
    secret_bin = to_bin(secret)
    print("Secret in bin " + str(secret_bin))
    print("Secret message to be hidden in binary form: " + secret_bin)
    secret_bin_len = len(secret_bin)
    print("Length of length: " + str(bin(secret_bin_len)[2:]))
    print("Length of the message in bits: " + str(secret_bin_len))
    secret_bin = bin(secret_bin_len)[2:] + to_bin("@#@#@") + secret_bin
    print("Length of delimiter: " + str(len(to_bin("@#@#@"))))
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
            print(end_of_msg_len)
            msg_len_bin = lsb_all[0:end_of_msg_len]
            msg_len = int(msg_len_bin, 2)
            print("Length of the uncovered message: " + str(msg_len) + " bits")
            start_of_msg_pointer = end_of_msg_len + len(delimiter)
            end_of_msg_pointer = start_of_msg_pointer + msg_len
            message = lsb_all[start_of_msg_pointer:end_of_msg_pointer]
            print("Message in bin: " + str(message))
            uncovered_message = to_ascii(message)
            return uncovered_message
        else:
            return False
    else:
        return False
