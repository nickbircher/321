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

    # Define the AES-CBC cipher
    am_cipher = AES.new(am_s, AES.MODE_CBC)
    a_iv = am_cipher.iv
    bm_cipher = AES.new(bm_s, AES.MODE_CBC)
    b_iv = bm_cipher.iv

    # Define the message and the initialization vector
    alice_message = b"This is a secret message from Alice."
    bob_message = b"This is a secret message from Bob."

    

    # Pad the message to a multiple of 16 bytes and encrypt it
    alice_ciphertext = am_cipher.encrypt(pad(alice_message, AES.block_size))

    bob_ciphertext = bm_cipher.encrypt(pad(bob_message, AES.block_size))

    # # Print the ciphertext
    # print("Ciphertext:", ciphertext.hex())

    # MALLORY DECRYPTION:
    # Mallory decrypts the ciphertext from Alice
    am_decrypt = AES.new(am_s, AES.MODE_CBC, a_iv)
    am_plainttext = unpad(am_decrypt.decrypt(alice_ciphertext), AES.block_size)

    # Print the decrypted message
    print("Decrypted message from Alice to Mallory:", am_plainttext.decode())
    
    # Mallory decrypts the ciphertext from Alice
    bm_decrypt = AES.new(bm_s, AES.MODE_CBC, b_iv)
    bm_plainttext = unpad(bm_decrypt.decrypt(bob_ciphertext), AES.block_size)

    # Print the decrypted message
    print("Decrypted message from Bob to Mallory:", bm_plainttext.decode())

    # MALLORY ENCRYPTION:
    
    # MALLORY ENCRYPTION:
    mallory_message_to_alice = b"Hi Alice"
    mallory_message_to_bob = b"Hi Bob"

    # Pad the messages to a multiple of 16 bytes and encrypt them
    mallory_ciphertext_to_alice = am_cipher.encrypt(pad(mallory_message_to_alice, AES.block_size))
    mallory_ciphertext_to_bob = bm_cipher.encrypt(pad(mallory_message_to_bob, AES.block_size))

    # Alice decrypts the message from Mallory
    alice_decrypt = AES.new(am_s, AES.MODE_CBC, a_iv)
    alice_plaintext_from_mallory = unpad(alice_decrypt.decrypt(mallory_ciphertext_to_alice), AES.block_size)
    try:
        alice_plaintext_from_mallory_str = alice_plaintext_from_mallory.decode('utf-8')
    except UnicodeDecodeError:
        alice_plaintext_from_mallory_str = alice_plaintext_from_mallory.decode('latin-1', errors='replace')
    print("Decrypted message from Mallory to Alice:", alice_plaintext_from_mallory_str)

    # Bob decrypts the message from Mallory
    bob_decrypt = AES.new(bm_s, AES.MODE_CBC, b_iv)
    bob_plaintext_from_mallory = unpad(bob_decrypt.decrypt(mallory_ciphertext_to_bob), AES.block_size)
    try:
        bob_plaintext_from_mallory_str = bob_plaintext_from_mallory.decode('utf-8')
    except UnicodeDecodeError:
        bob_plaintext_from_mallory_str = bob_plaintext_from_mallory.decode('latin-1', errors='replace')
    print("Decrypted message from Mallory to Bob:", bob_plaintext_from_mallory_str)







    # # Mallory encrypts her own message and sends to Bob
    # mb_ctext = bm_cipher.encrypt(pad(b"Hello Bob - Mallory", AES.block_size))

    # # Bob decrypts using his shared key with Mallory
    # mb_decrypt = AES.new(bm_s, AES.MODE_CBC, b_iv)
    # mb_plaintext = unpad(mb_decrypt.decrypt(mb_ctext), AES.block_size)
    # print(mb_plaintext.decode())

    # # print("Decrypted message to Bob from Mallory: ", mb_plaintext.decode())

if __name__ == "__main__":
    main()