import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def main():
    # Define the prime number q and the generator alpha
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    # Generate a random private key for Alice and Bob
    alice_private_key = random.randint(1, q-1) #Xa
    bob_private_key = random.randint(1, q-1) #Xb

    # Compute the public keys for Alice and Bob
    alice_public_key = pow(alpha, alice_private_key, q) # Ya
    bob_public_key = pow(alpha, bob_private_key, q) # Yb
    # q = mallory_public_key

    # Compute the shared secret key for Alice and Bob
        # alice shared key with Mallory
    alice_shared_key = pow(q, alice_private_key, q) #Yb ^Xa mod q = s

        # bob shared key with mallory
    bob_shared_key = pow(q, bob_private_key, q) #Ya ^ Xb mod q = s


    # # Print the shared secret keys
    # print("Alice's shared key:", alice_shared_key)
    # print("Bob's shared key:", bob_shared_key)

    # # Confirm that Alice and Bob have the same shared secret key
    # assert alice_shared_key == bob_shared_key

    # Compute the SHA-256 hash of the shared secret keys and truncate it to 16 bytes

    am_s = hashlib.sha256(str(alice_shared_key).encode()).digest()[:16]

    bm_s = hashlib.sha256(str(bob_shared_key).encode()).digest()[:16]

    if (am_s == bm_s):
        s = am_s
    else:
        raise TypeError

    # Define the AES-CBC cipher
    mallory_encrypt = AES.new(s, AES.MODE_CBC)
    iv = mallory_encrypt.iv

    mallory_decrypt = AES.new(s, AES.MODE_CBC, iv=iv)

    # Define the message and the initialization vector
    alice_message = b"This is a secret message from Alice."
    bob_message = b"This is a secret message from Bob."

    # Pad the message to a multiple of 16 bytes and encrypt it
    alice_ciphertext = mallory_encrypt.encrypt(pad(alice_message, AES.block_size))

    bob_ciphertext = mallory_encrypt.encrypt(pad(bob_message, AES.block_size))

    # # Print the ciphertext

    # MALLORY DECRYPTION:
    # Mallory decrypts the ciphertext from Alice
    am_plainttext = unpad(mallory_decrypt.decrypt(alice_ciphertext), AES.block_size)

    # Print the decrypted message
    print("Decrypted message from Alice to Mallory:", am_plainttext.decode())
    
    # Mallory decrypts the ciphertext from Alice
    bm_plainttext = unpad(mallory_decrypt.decrypt(bob_ciphertext), AES.block_size)

    # Print the decrypted message
    print("Decrypted message from Bob to Mallory:", bm_plainttext.decode())

    # MALLORY ENCRYPTION:

    # Mallory encrypts her own message and sends to Bob
    mb_ctext = mallory_encrypt.encrypt(pad(b"Hello Bob, from Mallory", AES.block_size))

    # Mallory encrypts her own message and sends to Alice
    ma_ctext = mallory_encrypt.encrypt(pad(b"Hello Alice, from Mallory", AES.block_size))

    # Bob decrypts using his shared key with Mallory
    mb_plaintext = unpad(mallory_decrypt.decrypt(mb_ctext), AES.block_size)
    print("Decrypted message to Mallory to Bob: ", mb_plaintext.decode())

    # Alice decrypts using his shared key with Mallory
    ma_plaintext = unpad(mallory_decrypt.decrypt(ma_ctext), AES.block_size)
    print("Decrypted message to Mallory to Alice: ", ma_plaintext.decode())

if __name__ == "__main__":
    main()