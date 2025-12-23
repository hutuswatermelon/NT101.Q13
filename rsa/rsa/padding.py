import hashlib
import hmac
import secrets
from .errors import MessageTooLarge, PaddingError


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, mask_len: int, hash_name: str = "sha256") -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        c = counter.to_bytes(4, "big")
        out.extend(hashlib.new(hash_name, seed + c).digest())
        counter += 1
    return bytes(out[:mask_len])


def oaep_encode(message: bytes, k: int, hash_name: str = "sha256", label: bytes = b"") -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(message) > k - 2 * h_len - 2:
        raise MessageTooLarge("Message too large for OAEP with this modulus.")
    l_hash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    seed = secrets.token_bytes(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    masked_db = _xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, h_len, hash_name)
    masked_seed = _xor_bytes(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, k: int, hash_name: str = "sha256", label: bytes = b"") -> bytes:
    h_len = hashlib.new(hash_name).digest_size
    if len(encoded) != k or k < 2 * h_len + 2:
        raise PaddingError("Invalid OAEP length.")
    if encoded[0] != 0:
        raise PaddingError("Invalid OAEP header.")
    masked_seed = encoded[1:1 + h_len]
    masked_db = encoded[1 + h_len:]
    seed_mask = mgf1(masked_db, h_len, hash_name)
    seed = _xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    db = _xor_bytes(masked_db, db_mask)
    l_hash = hashlib.new(hash_name, label).digest()
    if not hmac.compare_digest(db[:h_len], l_hash):
        raise PaddingError("Invalid OAEP label hash.")
    idx = db.find(b"\x01", h_len)
    if idx < 0:
        raise PaddingError("Invalid OAEP padding.")
    return db[idx + 1:]


def pss_encode(message: bytes, em_bits: int, salt_len: int = 32, hash_name: str = "sha256") -> bytes:
    h = hashlib.new(hash_name, message).digest()
    h_len = len(h)
    em_len = (em_bits + 7) // 8
    if em_len < h_len + salt_len + 2:
        raise PaddingError("Encoding error: intended length too short.")
    salt = secrets.token_bytes(salt_len)
    m_prime = b"\x00" * 8 + h + salt
    h2 = hashlib.new(hash_name, m_prime).digest()
    ps = b"\x00" * (em_len - salt_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h2, em_len - h_len - 1, hash_name)
    masked_db = _xor_bytes(db, db_mask)
    mask_bits = 8 * em_len - em_bits
    if mask_bits:
        masked_db = bytes([masked_db[0] & (0xFF >> mask_bits)]) + masked_db[1:]
    return masked_db + h2 + b"\xbc"


def pss_verify(message: bytes, encoded: bytes, em_bits: int, salt_len: int = 32, hash_name: str = "sha256") -> bool:
    h = hashlib.new(hash_name, message).digest()
    h_len = len(h)
    em_len = (em_bits + 7) // 8
    if len(encoded) != em_len or em_len < h_len + salt_len + 2:
        return False
    if encoded[-1] != 0xBC:
        return False
    masked_db = encoded[:em_len - h_len - 1]
    h2 = encoded[em_len - h_len - 1:-1]
    mask_bits = 8 * em_len - em_bits
    if mask_bits and masked_db[0] & (0xFF << (8 - mask_bits)):
        return False
    db_mask = mgf1(h2, em_len - h_len - 1, hash_name)
    db = _xor_bytes(masked_db, db_mask)
    if mask_bits:
        db = bytes([db[0] & (0xFF >> mask_bits)]) + db[1:]
    ps_len = em_len - h_len - salt_len - 2
    if db[:ps_len] != b"\x00" * ps_len or db[ps_len:ps_len + 1] != b"\x01":
        return False
    salt = db[-salt_len:]
    m_prime = b"\x00" * 8 + h + salt
    h3 = hashlib.new(hash_name, m_prime).digest()
    return hmac.compare_digest(h2, h3)

def pad_v1_encrypt(message: bytes, k: int) -> bytes:
    # 00 02 PS 00 M, with PS random non-zero bytes
    if len(message) > k - 11:
        raise MessageTooLarge("Message too large for RSA modulus (need chunking).")

    ps_len = k - 3 - len(message)
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.randbelow(256)
        if b != 0:
            ps.append(b)
    return b"\x00\x02" + bytes(ps) + b"\x00" + message

def unpad_v1_encrypt(padded: bytes) -> bytes:
    if len(padded) < 11 or padded[0:2] != b"\x00\x02":
        raise PaddingError("Invalid padding header.")
    sep = padded.find(b"\x00", 2)
    if sep < 0 or sep < 10:
        raise PaddingError("Invalid padding separator.")
    return padded[sep + 1:]
