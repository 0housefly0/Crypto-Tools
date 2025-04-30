a = 26513
b = 32321
def euclidean(p, q):
    while q != 0:
        p, q = q, p % q
    return p

def extended_gcd(p, q):
    """
    Extended Euclidean Algorithm.
    Returns a tuple (gcd, u, v) such that:
    p*u + q*v = gcd
    """
    if q == 0:
        return (p, 1, 0)
    else:
        gcd_val, u1, v1 = extended_gcd(q, p % q)
        u = v1
        v = u1 - (p // q) * v1
        return (gcd_val, u, v)
print(extended_gcd(a, b))


