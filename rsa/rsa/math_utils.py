from .errors import InvalidKey

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def egcd(a: int, b: int):
    # returns (g, x, y) where ax + by = g
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise InvalidKey("No modular inverse exists for given e and phi(n).")
    return x % m

def modexp(base: int, exp: int, mod: int) -> int:
    # implemented for coursework (instead of pow(base, exp, mod))
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result

def k_bytes_from_n(n: int) -> int:
    # Convert bit length to full bytes needed to represent n.
    return (n.bit_length() + 7) // 8
