from typing import List, TypeAlias, TypedDict

CtBool: TypeAlias = int

CtUint: TypeAlias = int

CtString: TypeAlias = tuple[List[int]]

class ItBool(TypedDict):
    ciphertext: int
    signature: bytes

class ItUint(TypedDict):
    ciphertext: int
    signature: bytes

class ItStringCiphertext(TypedDict):
    value: List[int]

class ItString(TypedDict): 
    ciphertext: ItStringCiphertext
    signature: List[bytes]


class CtUint256(TypedDict):
    ciphertextHigh: int
    ciphertextLow: int


class ItUint256Ciphertext(TypedDict):
    ciphertextHigh: int
    ciphertextLow: int


class ItUint256(TypedDict):
    ciphertext: ItUint256Ciphertext
    signature: bytes
