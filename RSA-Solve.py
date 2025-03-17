from Crypto.Util.number import long_to_bytes

def rsa_decrypt(c, e, n, p, q):
    # Verify the RSA parameters
    print(f"Verifying RSA parameters:")
    print(f"n = {p * q}")
    print(f"Actual n = {n}")
    print(f"n matches p*q: {p * q == n}")
    
    # Calculate totient (Euler's totient function)
    order = (p-1)*(q-1)
    
    # Calculate private key
    d = pow(e, -1, order)
    
    # Decrypt
    m = pow(c, d, n)
    
    # Convert to bytes
    try:
        out = long_to_bytes(m)
        print(f"\nDecrypted message: {out}")
        print(f"Decrypted message (hex): {out.hex()}")
        print(f"Decrypted message (int): {m}")
        
        # Additional checks
        # Verify encryption would return the original ciphertext
        encrypted_check = pow(m, e, n)
        print(f"\nVerification:")
        print(f"Re-encrypted message matches original ciphertext: {encrypted_check == c}")
        print(out)
    except Exception as ex:
        print(f"Error decrypting: {ex}")

# Your specific parameters
e = 65537
c = 0
p = 0
q = 0
n = p * q

# Run decryption