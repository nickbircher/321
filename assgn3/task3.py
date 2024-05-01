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

    if (d1 == m1):
        print("successfully decoded message 1.")

    m2 = int.from_bytes(b"mystring", byteorder='little')

    c2 = pow(m2, e, n)

    d2 = pow(c2, d, n)
    
    if(d2 == m2):
        print("successfully decoded message 2.")

    m3 = int.from_bytes(b"this string is a little longer", byteorder='little')

    c3 = pow(m3, e, n)

    d3 = pow(c3, d, n)
    print("d3:", m3.to_bytes(byteorder='little'))
    if(d3 == m3):
        print("successfully decoded message 3.")

    
    # Mallory's MITM attack

    # Bob's message to 
    m4 = int.from_bytes(b"mystring", byteorder='little')


    c4 = pow(m4, e, n)

    d4 = pow(c4, d, n)
    
    if(d4 == m4):
        print("successfully decoded message 4.")



    return


if __name__=="__main__":
    main()