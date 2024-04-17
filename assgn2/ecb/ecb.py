from Crypto.Cipher import AES
import sys
sys.path.insert(0, "..")
import pkcs7


def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pkcs7.pkcs7_pad(plaintext, AES.block_size)
    ciphertext = b""
    for i in range(0, len(padded_message), AES.block_size):
        block = padded_message[i:i+AES.block_size]
        ciphertext += cipher.encrypt(block)
    return ciphertext


def encrypt_file(filename, key):
    with open(filename, "rb") as f:
        file = f.read()

    # Remove the header of the BMP file
    header = file[:54]
    file = file[54:]

    # Add the header back to the encrypted file and write to new file
    ciphertext = header + ecb_encrypt(key, file)

    # filename[3:] removes the "../" from the filename
    with open("ecb-encrypted-" + filename[3:], "wb") as f:
        f.write(ciphertext)


def main():
    sixteen_byte_key = b"iisixteenbytekey"
    encrypt_file("../cp-logo.bmp", sixteen_byte_key)
    encrypt_file("../mustang.bmp", sixteen_byte_key)

if __name__ == "__main__":
    main()