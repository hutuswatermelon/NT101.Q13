class RSAError(Exception):
    """Base error for RSA core."""
    pass

class InvalidKey(RSAError):
    pass

class MessageTooLarge(RSAError):
    pass

class PaddingError(RSAError):
    pass

class SignatureError(RSAError):
    pass

class FormatError(RSAError):
    pass