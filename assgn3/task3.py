import math
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

def main():
    e = 65537
    p_seed = random.randint(1, 2048)
    q_seed = random.randint(1, 2048)
    p = getPrime(p_seed)
    q = getPrime(q_seed)
    # q = 11
    # p = 17
    while (q==p):
        q = getPrime(2048)
    n = p*q
    eulers_n = (p-1)*(q-1)
    print(e,n)
   
    d = int(float(eulers_n + 1)/(float(e)))
    print(d,n)
    
    #PU = {e, n}
    #PR = {d, n}

    #m2 = ''.join(r'\x{02:x}'.format(ord(c)) for c in "mystring")
    
    m1 = 88

    c1 = pow(m1, e,n)

    d1 = pow(c1, d, n)

    print(d1)


    return


if __name__=="__main__":
    main()