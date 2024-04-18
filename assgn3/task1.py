import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def main():
    # Define the prime number q and the generator alpha
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    # Generate a random private key for Alice and Bob
    alice_private_key = random.randint(1, q-1)
    bob_private_key = random.randint(1, q-1)

    # Compute the public keys for Alice and Bob
    alice_public_key = pow(alpha, alice_private_key, q)
    bob_public_key = pow(alpha, bob_private_key, q)

    # Compute the shared secret key for Alice and Bob
    alice_shared_key = pow(bob_public_key, alice_private_key, q)
    bob_shared_key = pow(alice_public_key, bob_private_key, q)

    # Print the shared secret keys
    print("Alice's shared key:", alice_shared_key)
    print("Bob's shared key:", bob_shared_key)

    # Confirm that Alice and Bob have the same shared secret key
    assert alice_shared_key == bob_shared_key

    # Compute the SHA-256 hash of the shared secret key and truncate it to 16 bytes
    key = hashlib.sha256(str(alice_shared_key).encode()).digest()[:16]

    # Define the AES-CBC cipher
    cipher = AES.new(key, AES.MODE_CBC)

    # Define the message and the initialization vector
    message = b"This is a secret message."
    iv = cipher.iv

    # Pad the message to a multiple of 16 bytes and encrypt it
    ciphertext = cipher.encrypt(pad(message, AES.block_size))

    # Print the ciphertext
    print("Ciphertext:", ciphertext.hex())

    # Decrypt the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Print the decrypted message
    print("Decrypted message:", plaintext.decode())


if __name__ == "__main__":
    main()