from Crypto.Cipher import AES  
import sys
sys.path.insert(0, "..")
import pkcs7  
import os


KEY = os.urandom(16)
IV = os.urandom(16)

def cbc_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher object with ECB mode
    plaintext = pkcs7.pkcs7_pad(plaintext, AES.block_size)  # Pad plaintext using PKCS7 padding
    ciphertext = bytes()  # Initialize an empty byte string to store the ciphertext
    for i in range(0, len(plaintext), AES.block_size):
        block = plaintext[i:i+AES.block_size]  # Get a block of plaintext
        xor_block = bytes([b ^ iv[j % len(iv)] for j, b in enumerate(block)])  # XOR the block with the IV
        ciphered_block = cipher.encrypt(xor_block)  # Encrypt the XORed block using AES cipher
        ciphertext += ciphered_block  # Append the encrypted block to the ciphertext
        iv = ciphered_block  # Update the IV with the encrypted block
    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher object with ECB mode
    ciphertext = ciphertext  
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError("Ciphertext is not a multiple of the block size")  # Raise an error if the ciphertext length is not a multiple of the block size
    plaintext = bytes()  # Initialize an empty byte string to store the plaintext
    for i in range(0, len(ciphertext), AES.block_size):
        block = ciphertext[i:i+AES.block_size]  # Get a block of ciphertext
        deciphered_block = cipher.decrypt(block)  # Decrypt the block using AES cipher
        xor_block = bytes([b ^ iv[j % len(iv)] for j, b in enumerate(deciphered_block)])  # XOR the decrypted block with the IV
        plaintext += xor_block  # Append the XORed block to the plaintext
        iv = block  # Update the IV with the current block
    
    plaintext = pkcs7.pkcs7_unpad(plaintext, AES.block_size)  # Unpad the plaintext using PKCS7 padding
    
    return plaintext


def encrypt_file(filename, key, iv):
    with open(filename, "rb") as f:
        file = f.read()

    # Remove the header of the BMP file
    header = file[:54]
    file = file[54:]

    # Add the header back to the encrypted file and write to new file
    ciphertext = header + cbc_encrypt(file, key, iv)

    # filename[3:] removes the "../" from the filename
    with open("cbc-encrypted-" + filename[3:], "wb") as f:
        f.write(ciphertext)


def main():
    encrypt_file("../cp-logo.bmp", KEY, IV)
    encrypt_file("../mustang.bmp", KEY, IV)

if __name__ == "__main__":
    main()