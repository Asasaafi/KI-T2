import os
import binascii
from Crypto.Cipher import DES
from typing import Tuple

BLOCK_SIZE = 8

def generate_key_hex() -> str:
    """Generate a random 8-byte (64-bit) DES key and return as hex string (16 hex chars)."""
    key = os.urandom(8)
    return binascii.hexlify(key).decode()

def key_hex_to_bytes(hexkey: str) -> bytes:
    """Convert hex key string to bytes, validating length (must be 8 bytes)."""
    b = binascii.unhexlify(hexkey)
    if len(b) != 8:
        raise ValueError("DES key must be exactly 8 bytes (16 hex characters).")
    return b

def pad_pkcs7(data: bytes) -> bytes:
    """Apply PKCS#7 padding for block size 8."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def unpad_pkcs7(padded: bytes) -> bytes:
    """Remove PKCS#7 padding. Raises ValueError if padding invalid."""
    if not padded or len(padded) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length.")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes.")
    return padded[:-pad_len]

def encrypt_des_cbc(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using DES-CBC.
    Returns (iv, ciphertext). IV is 8 bytes.
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes for DES.")
    iv = os.urandom(BLOCK_SIZE)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pad_pkcs7(plaintext)
    ct = cipher.encrypt(padded)
    return iv, ct

def decrypt_des_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt DES-CBC ciphertext with given IV (8 bytes). Returns plaintext (unpadded).
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes for DES.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 8 bytes for DES-CBC.")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be multiple of block size.")
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad_pkcs7(padded)

# bantu kecil untuk konversi hex
def to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def from_hex(s: str) -> bytes:
    return binascii.unhexlify(s)

# Bagian uji coba mandiri (dijalankan jika file ini dieksekusi langsung)
if __name__ == "__main__":
    print("=== crypto_utils.py test ===")
    
    hexkey = generate_key_hex()
    key = key_hex_to_bytes(hexkey)
    print("Generated DES key (hex):", hexkey)

    pt = b"Hallo DES! Ini pesan percobaan."
    print("Plaintext:", pt)

    iv, ct = encrypt_des_cbc(key, pt)
    print("IV (hex):", to_hex(iv))
    print("Ciphertext (hex):", to_hex(ct))

    pt2 = decrypt_des_cbc(key, iv, ct)
    print("Decrypted plaintext:", pt2)

    assert pt == pt2, "Round-trip failed!"
    print("Round-trip OK  ")