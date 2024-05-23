import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

def extended_euclidean(a, b):
    if b == 0:
        return a, 1, 0
    else:
        gcd, x, y = extended_euclidean(b, a % b)
        return gcd, y, x - (a // b) * y

def calculate_d(e, eulers_n):
    _, x, _ = extended_euclidean(e, eulers_n)
    return x % eulers_n

def main():
    e = 65537
    p = getPrime(2048)
    q = getPrime(2048)
    # q = 11
    # p = 17
    while (q==p):
        q = getPrime(2048)
    n = p*q
    eulers_n = (p-1)*(q-1)
    #print("public: ",e,n)
   
    d = calculate_d(e, eulers_n)
    #print("private: ", d,n)
    
    #PU = {e, n}
    #PR = {d, n}
    
    m1 = 88

    c1 = pow(m1, e,n)

    #print("cypher: ", c1)

    d1 = pow(c1, d, n)

    #print("decrpyt:", d1)

    # if (d1 == m1):
    #     print("successfully decoded message 1.")

    # m2 = int.from_bytes(b"mystring", byteorder='little')

    # c2 = pow(m2, e, n)

    # d2 = pow(c2, d, n)
    
    # if(d2 == m2):
    #     print("successfully decoded message 2.")

    # m3 = int.from_bytes(b"this string is a little longer", byteorder='little')

    # c3 = pow(m3, e, n)

    # d3 = pow(c3, d, n)
    # if(d3 == m3):
    #     print("successfully decoded message 3.")

    #Bob calculation of private key
    e = 65537
    p = getPrime(2048)
    q = getPrime(2048)
    while (q==p):
        q = getPrime(2048)
    n = p*q
    eulers_n = (p-1)*(q-1)
    d = calculate_d(e, eulers_n)

    #Here, Bob sends to Mallory his hashed key
    bob_s = random.randint(0, n)
    c = pow(bob_s, e,n) # this is the key intended to be sent

    # and Mallory sends her 'key' to Alice
    c = 0
    # Mallory sends 0 instead so she can calculate hash
    alice_s = pow(c, d, n)

    alice_mallory_shared_key = hashlib.sha256(str(alice_s).encode()).digest()[:16]
    
    m1 = b"Hi Bob, this is from Alice"

    encrypt = AES.new(alice_mallory_shared_key, AES.MODE_CBC)
    iv = encrypt.iv

    alice_ciphertext = encrypt.encrypt(pad(m1, AES.block_size))

    decrypt = AES.new(alice_mallory_shared_key, AES.MODE_CBC, iv=iv)

    d1 = unpad(decrypt.decrypt(alice_ciphertext), AES.block_size)

    print(m1)
    print(d1.decode())

    if (m1 == d1):
        print("Mallory successfully intercepted message from Alice to BOB: ", d1.decode())
    return


if __name__=="__main__":
    main()