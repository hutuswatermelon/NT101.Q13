import base64

def text_to_bytes(text: str) -> bytes:
    return text.encode("utf-8")

def bytes_to_text(data: bytes) -> str:
    return data.decode("utf-8")

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))
