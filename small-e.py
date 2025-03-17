import gmpy2
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


e = 7  # Small public exponent

ciphertext = 0


plaintext = gmpy2.iroot(ciphertext, e)

print(plaintext)




