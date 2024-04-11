import sys
sys.path.insert(0, "..")
from pkcs7 import pkcs7_pad  
from cbc import cbc_encrypt, cbc_decrypt
from Crypto.Cipher import AES


KEY = b"iisixteenbytekey"
IV = b"sixteenbytekeyii"


def submit():
    user_input = input("Enter a string: ")
    # url encode ";" and "="
    user_input = user_input.replace(";", "%3B")
    user_input = user_input.replace("=", "%3D")
    user_input = "userid=456;userdata=" + user_input + ";session-id=31337"

    # pad the final string
    pkcs7_pad(user_input, AES.block_size)

    return cbc_encrypt(user_input, KEY, IV)


def verify(encrypted_string):
    decrypted_string = cbc_decrypt(encrypted_string, KEY, IV)
    # parse string for the pattern ";admin=true"
    if ";admin=true;" in decrypted_string:
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


def flip_bits(temp):
    print()


def main():
    print()

if __name__ == "__main__":
    main()