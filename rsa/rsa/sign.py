from .models import PublicKey, PrivateKey
from .math_utils import modexp, k_bytes_from_n
from .padding import pss_encode, pss_verify
from .errors import SignatureError

def sign_bytes(data: bytes, priv: PrivateKey) -> bytes:
    """
    RSA-PSS with SHA-256.
    """
    em_bits = priv.n.bit_length() - 1
    em = pss_encode(data, em_bits, salt_len=32, hash_name="sha256")
    m = int.from_bytes(em, "big")
    if m >= priv.n:
        raise SignatureError("Encoded message too large for modulus.")
    s = modexp(m, priv.d, priv.n)
    k = k_bytes_from_n(priv.n)
    return s.to_bytes(k, "big")

def verify_bytes(data: bytes, sig: bytes, pub: PublicKey) -> bool:
    k = k_bytes_from_n(pub.n)
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    m = modexp(s, pub.e, pub.n)
    em = m.to_bytes(k, "big")
    em_bits = pub.n.bit_length() - 1
    return pss_verify(data, em, em_bits, salt_len=32, hash_name="sha256")
