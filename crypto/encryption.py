# === crypto/encryption.py ===
# Реалізація шифрування / розшифрування хешу бюлетеня

from ecpy.curves import Curve, Point
import secrets

# Використання тієї ж кривої Ed25519
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Шифрування ElGamal'ом на кривій Едвардса
def encrypt_hash(hash_scalar: int, pub_key: Point) -> tuple[Point, Point]:
    M = hash_scalar * G
    r = secrets.randbelow(q)
    C1 = r * G
    C2 = M + r * pub_key
    return C1, C2

# Розшифрування з використанням приватного ключа
def decrypt_ciphertext(C1: Point, C2: Point, priv_key: int) -> Point:
    S = priv_key * C1
    M_decrypted = C2 - S
    return M_decrypted

# Перевірка відповідності (наприклад, на боці серверу або секретаря)
def verify_decrypted_point(M_decrypted: Point, hash_scalar: int) -> bool:
    M_expected = hash_scalar * G
    return M_decrypted == M_expected