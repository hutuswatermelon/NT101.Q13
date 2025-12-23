import secrets
from .math_utils import modexp

_SMALL_PRIMES = [2,3,5,7,11,13,17,19,23,29,31,37]

def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n - 1 = d * 2^s
    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1

    def witness(a: int) -> bool:
        x = modexp(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return True
        return False

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        if not witness(a):
            return False
    return True

def generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("bits too small for prime generation.")
    while True:
        x = secrets.randbits(bits)
        x |= (1 << (bits - 1))  # set top bit
        x |= 1                  # make odd
        if is_probable_prime(x):
            return x