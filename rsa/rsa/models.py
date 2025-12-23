from dataclasses import dataclass

@dataclass(frozen=True)
class PublicKey:
    e: int
    n: int

@dataclass(frozen=True)
class PrivateKey:
    d: int
    n: int

@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey