import base64
import xml.etree.ElementTree as ET
from .models import PublicKey, PrivateKey
from .errors import InvalidKey


def _int_to_b64(n: int) -> str:
    if n <= 0:
        raise InvalidKey("Invalid RSA integer.")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.b64encode(n_bytes).decode("ascii")


def _b64_to_int(text: str) -> int:
    raw = base64.b64decode(text.encode("ascii"))
    return int.from_bytes(raw, "big")


def _load_xml(path: str) -> ET.Element:
    try:
        tree = ET.parse(path)
        return tree.getroot()
    except Exception as exc:
        raise InvalidKey("Invalid RSA XML key file.") from exc


def _write_xml(root: ET.Element, path: str) -> None:
    tree = ET.ElementTree(root)
    tree.write(path, encoding="utf-8", xml_declaration=False)

def save_public_key(pub: PublicKey, path: str) -> None:
    root = ET.Element("RSAKeyValue")
    n = ET.SubElement(root, "Modulus")
    e = ET.SubElement(root, "Exponent")
    n.text = _int_to_b64(pub.n)
    e.text = _int_to_b64(pub.e)
    _write_xml(root, path)

def save_private_key(priv: PrivateKey, path: str) -> None:
    root = ET.Element("RSAKeyValue")
    n = ET.SubElement(root, "Modulus")
    d = ET.SubElement(root, "D")
    n.text = _int_to_b64(priv.n)
    d.text = _int_to_b64(priv.d)
    _write_xml(root, path)

def load_public_key(path: str) -> PublicKey:
    root = _load_xml(path)
    if root.tag != "RSAKeyValue":
        raise InvalidKey("Not an RSA XML public key.")
    modulus = root.findtext("Modulus")
    exponent = root.findtext("Exponent")
    if not modulus or not exponent:
        raise InvalidKey("Missing Modulus or Exponent.")
    return PublicKey(_b64_to_int(exponent), _b64_to_int(modulus))

def load_private_key(path: str) -> PrivateKey:
    root = _load_xml(path)
    if root.tag != "RSAKeyValue":
        raise InvalidKey("Not an RSA XML private key.")
    modulus = root.findtext("Modulus")
    d = root.findtext("D")
    if not modulus or not d:
        raise InvalidKey("Missing Modulus or D.")
    return PrivateKey(_b64_to_int(d), _b64_to_int(modulus))
