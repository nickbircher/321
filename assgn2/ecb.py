from Crypto.Cipher import AES
from base64 import b64decode
from util import hex_to_bytes, bytes_to_hex
import pkcs7


def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pkcs7.pkcs7_pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext


def ecb_decrypt(key, ciphertext):
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("Ciphertext is not a multiple of the block size")
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    try:
        message = pkcs7.pkcs7_unpad(padded_message, AES.block_size)
    except ValueError:
        raise ValueError("Invalid padding")
    return message


def encrypt_file(filename, key):
    with open(filename, "rb") as f:
        file = f.read()

    # Remove the header of the BMP file
    header = file[:54]
    file = file[54:]

    # Add the header back to the encrypted file and write to new file
    ciphertext = header + ecb_encrypt(key, file)

    with open("encrypted-" + filename, "wb") as f:
        f.write(ciphertext)


def main():
    sixteen_byte_key = b"iisixteenbytekey"
    encrypt_file("cp-logo.bmp", sixteen_byte_key)
    encrypt_file("mustang.bmp", sixteen_byte_key)

if __name__ == "__main__":
    main()