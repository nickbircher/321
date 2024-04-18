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


def flip_bits(ciphertext):
    # block 1: userid%3D456%3Bu
    # block 2: serdata%3D123456 
    # block 3: .admin1true.1234

    original = "serdata%3D123456".encode('utf-8')
    target = ";admin=true;".encode('utf-8') + bytes([4]) * 4

    mask = xor(original, target)

    attack_block = pkcs7_pad(xor(mask, ciphertext), AES.block_size)

    # changing Ci will change Pi+1
    #print(cbc_decrypt(ciphertext, KEY, IV).decode('utf-8'))
    #print(cbc_decrypt(attack_block, KEY, IV).decode('utf-8'))
    return ciphertext[:32] + attack_block + ciphertext[32:]


def main():
    ciphertext = submit()
    print(verify(ciphertext))
    modified_ciphertext = flip_bits(ciphertext)
    print(verify(modified_ciphertext))

if __name__ == "__main__":
    main()