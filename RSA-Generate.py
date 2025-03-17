from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def is_coprime(a, b):
    while b:
        a, b = b, a % b
    return a == 1

# Check if p and q are large enough for CRT optimization
def check_for_CRT(p, q, e, order):
    # Ensure p and q are sufficiently large compared to e
    # CRT will be more useful if p and q are large enough, so we check if the primes
    # are significantly larger than e to allow CRT to speed up decryption.
    return p > e and q > e and is_coprime(e, order)

flag = b"{1_l0ve_R1Ves+_Sh@m1r_AdleMan}"
adsad = False
while not adsad:
    p = getPrime(4096)
    q = getPrime(4096)
    e = 65537
    n = p * q
    order = (p-1)*(q-1)
    
    # Ensure e is coprime with order and check if CRT can be used
    if not is_coprime(e, order):
        print('failed')
        break
    if check_for_CRT(p, q, e, order) == True:
        print("Using CRT optimization")
        # Verify decryption works
    enc = pow(bytes_to_long(flag), e, n)
    d = pow(e, -1, order)
    m = pow(enc, d, n)
    if m == bytes_to_long(flag):
        print("p = {}".format(p))
        print("q = {}".format(q))
        print("e = {}".format(e))
        print("n = {}".format(n))
        print("ct = {}".format(enc))
        adsad = True

# Decryption script using CRT optimization
def decrypt_with_CRT(ct, e, n, p, q):
    order = (p-1)*(q-1)
    
    # Compute the modular inverse of e modulo p-1 and q-1
    dp = pow(e, -1, p-1)
    dq = pow(e, -1, q-1)
    qinv = pow(q, -1, p)

    # Step 1: Compute the ciphertext modulo p and q
    mp = pow(ct, dp, p)
    mq = pow(ct, dq, q)

    # Step 2: Use the Chinese Remainder Theorem to combine the results
    h = (qinv * (mp - mq)) % p
    m = mq + h * q
    
    return long_to_bytes(m)

# Decrypt and print the flag using CRT optimization
decrypted_flag = decrypt_with_CRT(enc, e, n, p, q)