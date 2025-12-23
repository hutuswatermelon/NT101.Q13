from .models import PublicKey, PrivateKey, KeyPair
from .prime import generate_prime
from .math_utils import gcd, modinv, modexp, k_bytes_from_n
from .padding import oaep_encode, oaep_decode
from .errors import InvalidKey, RSAError

def generate_keypair(bits: int = 1024, e: int = 65537) -> KeyPair:
    if bits < 256:
        raise ValueError("Use >=256 bits (1024+ recommended for coursework).")
    if e <= 1 or (e % 2 == 0):
        raise ValueError("e should be an odd integer > 1 (commonly 65537).")

    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            continue

        d = modinv(e, phi)
        return KeyPair(PublicKey(e, n), PrivateKey(d, n))

def encrypt_block(message: bytes, pub: PublicKey) -> bytes:
    k = k_bytes_from_n(pub.n)
    padded = oaep_encode(message, k)
    m = int.from_bytes(padded, "big")
    if m >= pub.n:
        raise RSAError("OAEP encoding out of range for modulus.")
    c = modexp(m, pub.e, pub.n)
    return c.to_bytes(k, "big")



def decrypt_block(cipher: bytes, priv: PrivateKey) -> bytes:
    k = k_bytes_from_n(priv.n)

    if len(cipher) != k:
        raise RSAError("Ciphertext block length mismatch")

    c = int.from_bytes(cipher, "big")
    m = modexp(c, priv.d, priv.n)

    padded = m.to_bytes(k, "big")
    return oaep_decode(padded, k)



def max_message_len(pub_or_priv_n: int) -> int:
    # for OAEP with SHA-256: k - 2*hLen - 2
    k = k_bytes_from_n(pub_or_priv_n)
    return k - 2 * 32 - 2

def encrypt_bytes(data: bytes, pub: PublicKey) -> bytes:
    """
    Encrypt arbitrary-length bytes by chunking into (k-11) blocks.
    Output is concatenated ciphertext blocks, each exactly k bytes.
    """
    k = k_bytes_from_n(pub.n)
    mmax = k - 11
    out = bytearray()
    for i in range(0, len(data), mmax):
        chunk = data[i:i+mmax]
        out += encrypt_block(chunk, pub)
    return bytes(out)

def decrypt_bytes(cipher_all: bytes, priv: PrivateKey) -> bytes:
    """
    Decrypt concatenated ciphertext blocks (each k bytes).
    """
    k = k_bytes_from_n(priv.n)
    if len(cipher_all) % k != 0:
        raise RSAError("Ciphertext length is not a multiple of block size.")
    out = bytearray()
    for i in range(0, len(cipher_all), k):
        block = cipher_all[i:i+k]
        out += decrypt_block(block, priv)
    return bytes(out)
