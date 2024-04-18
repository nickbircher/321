import sys
sys.path.insert(0, "..")
from pkcs7 import pkcs7_pad  
from cbc import cbc_encrypt, cbc_decrypt
from Crypto.Cipher import AES
import os
import urllib.parse


KEY = os.urandom(16)
IV = os.urandom(16)


# XOR function for byte strings
def xor(byte_string, key):
    result = b""
    for i in range(len(byte_string)):
        result += bytes([byte_string[i] ^ key[i % len(key)]])
    return result


def submit():
    user_input = input("Enter a string: ")
    
    user_input = "userid=456;userdata=" + user_input + ";session-id=31337"

    # url encode ";" and "="
    user_input = user_input.replace(";", urllib.parse.quote(";"))
    user_input = user_input.replace("=", urllib.parse.quote("="))

    # pad the final string
    user_input = pkcs7_pad(bytes(user_input, 'utf-8'), AES.block_size)

    return cbc_encrypt(user_input, KEY, IV)


def verify(encrypted_string):
    decrypted_string = cbc_decrypt(encrypted_string, KEY, IV)
    # parse string for the pattern ";admin=true"
    decrypted_string = decrypted_string.decode('utf-8')
    print(decrypted_string)
    if ";admin=true" in decrypted_string:
        return True
    else:
        return False
    

def calculate_bitmasks(original, target):
    bitmasks = []

    for i in range(len(original)):
        # Calculate the bitmask
        bitmask = ord(original[i]) ^ ord(target[i])
        bitmasks.append(bitmask)

    return bitmasks


def flip_bits(ciphertext):
    # At this point plaintext should be:
    # "userid=456;userdata=...;session-id=31337"
    # block 1: userid=456;userd
    # block 2: ata=12345678901;
    # block 3: session-id=31337

    ciphertext_chars = list(ciphertext)

    # Add junk block of userid=456;userd as the second block
    ciphertext_chars = ciphertext_chars[:16] + ciphertext_chars[:16] + ciphertext_chars[16:]

    # We want to change "userid=456;" to ";admin=true"
    original = ("userid%3D45".encode('utf-8') + bytes([5]) * 5).decode('utf-8')  # 11 characters long w/ padding
    target = (";admin=true".encode('utf-8') + bytes([5]) * 5).decode('utf-8')  # 11 characters long w/ padding

    # Calculate the bitmasks
    bitmasks = calculate_bitmasks(original, target)

    for i, mask in enumerate(bitmasks):
        # Flip bits in the second block by XORing with the mask
        ciphertext_chars[i] ^= mask


    # Convert the list of characters back to a byte string
    modified_ciphertext = bytes(ciphertext_chars)
    print(modified_ciphertext)
    return modified_ciphertext


def revise_flip_bits(ciphertext):
    original = "userid%3D45".encode('utf-8') + bytes([5]) * 5
    target = ";admin=true".encode('utf-8') + bytes([5]) * 5

    mask = xor(original, target)

    attack_block = pkcs7_pad(xor(mask, ciphertext[:16]), AES.block_size)

    # changing Ci will change Pi+1
    print(cbc_decrypt(ciphertext, KEY, IV).decode('utf-8'))
    print(cbc_decrypt(attack_block, KEY, IV).decode('utf-8'))
    return attack_block + ciphertext


def main():
    ciphertext = submit()
    print(verify(ciphertext))
    modified_ciphertext = revise_flip_bits(ciphertext)
    print(verify(modified_ciphertext))

if __name__ == "__main__":
    main()