# Encrypt-or-Hide
**An application allowing to encrypt and hide confidential messages in digital images. The project is carried out as part of an engineering thesis.**

This application allows performing steganography and cryptography processes using digital images as information carriers.

The first option (**steganography**) uses .png files as cover-image to hide (and later uncover) secret files or text messages as either plaintext or cryptogram through an LSB method. Polish characters are supported only when a secret message is in the form of a plaintext (utf-8 encoding), contrary to being encrypted before embedding (latin-1 encoding).
</br>**Cryptography** functionality lets the user encrypt (and later decrypt) a confidential image using an AES algorithm and make it unreadable to any operating system.

When encrypting either text or image, the encryption mode can be chosen by the user. Two available modes are CFB and CBC.
When performing embedding of the message, statistics of the process are given. Information includes: percentage of bits changed in the process and PSNR and MSE values as indicators of the severity of changes made to the cover image.

**All images by *rawpixel.com* and by self-creation.**</br>
Application made by Karolina Głowińska as part of an engineering thesis at AGH University of Science and Technology.
