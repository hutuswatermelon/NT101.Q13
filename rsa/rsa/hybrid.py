import json
import hmac
import hashlib
import os

from .aes import aes_ctr_crypt
from .cipher import encrypt_block, decrypt_block
from .codec import b64e, b64d
from .errors import RSAError, FormatError
from .models import PublicKey, PrivateKey
from .sign import sign_bytes, verify_bytes

_VERSION = 1
_ALG = "RSA-OAEP+AES-CTR+HMAC-SHA256"


def _payload_for_sig(enc_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    return b"HYB1" + enc_key + iv + ciphertext + tag


def encrypt_hybrid(data: bytes, recipient_pub: PublicKey, sender_priv: PrivateKey | None = None) -> bytes:
    aes_key = os.urandom(16)
    mac_key = os.urandom(16)
    iv = os.urandom(16)
    ciphertext = aes_ctr_crypt(aes_key, iv, data)
    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()

    key_blob = aes_key + mac_key
    enc_key = encrypt_block(key_blob, recipient_pub)

    payload = _payload_for_sig(enc_key, iv, ciphertext, tag)
    sig = sign_bytes(payload, sender_priv) if sender_priv else b""

    obj = {
        "v": _VERSION,
        "alg": _ALG,
        "ek": b64e(enc_key),
        "iv": b64e(iv),
        "ct": b64e(ciphertext),
        "tag": b64e(tag),
        "sig": b64e(sig) if sig else "",
    }
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def decrypt_hybrid(
    blob: bytes,
    recipient_priv: PrivateKey,
    sender_pub: PublicKey | None = None,
    verify_sig: bool = True,
) -> tuple[bytes, bool | None]:
    try:
        obj = json.loads(blob.decode("utf-8"))
    except Exception as exc:
        raise FormatError("Invalid encrypted envelope.") from exc

    if obj.get("v") != _VERSION or obj.get("alg") != _ALG:
        raise FormatError("Unsupported envelope version or algorithm.")

    try:
        enc_key = b64d(obj["ek"])
        iv = b64d(obj["iv"])
        ciphertext = b64d(obj["ct"])
        tag = b64d(obj["tag"])
        sig = b64d(obj["sig"]) if obj.get("sig") else b""
    except Exception as exc:
        raise FormatError("Malformed envelope fields.") from exc

    key_blob = decrypt_block(enc_key, recipient_priv)
    if len(key_blob) != 32:
        raise RSAError("Invalid key blob length.")
    aes_key = key_blob[:16]
    mac_key = key_blob[16:]

    expected_tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise RSAError("Invalid authentication tag.")

    payload = _payload_for_sig(enc_key, iv, ciphertext, tag)
    sig_ok = None
    if sig and verify_sig:
        if not sender_pub:
            raise RSAError("Signature present but sender public key missing.")
        sig_ok = verify_bytes(payload, sig, sender_pub)
        if not sig_ok:
            raise RSAError("Signature verification failed.")

    plaintext = aes_ctr_crypt(aes_key, iv, ciphertext)
    return plaintext, sig_ok
