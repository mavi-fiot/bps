# kzp/crypto_logic.py

from ecpy.curves import Curve, Point
import secrets

# Крива Едвардса Ed25519
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# 🔐 Генерація ключів сервера
_server_priv = secrets.randbelow(q)
_server_pub = _server_priv * G

# 🔐 Генерація ключів секретаря
_secretary_priv = secrets.randbelow(q)
_secretary_pub = _secretary_priv * G

def elgamal_encrypt(M: Point, pub_key: Point):
    r = secrets.randbelow(q)
    C1 = r * G
    C2 = M + r * pub_key
    return C1, C2

def elgamal_decrypt(C1: Point, C2: Point, priv_key: int) -> Point:
    return C2 - priv_key * C1

def verify_decrypted_point(M: Point, hash_scalar: int) -> bool:
    expected = hash_scalar * G
    return M == expected

def get_curve_params():
    """Повертає криву, генератор і порядок."""
    return curve, G, q

def get_server_keys():
    """Повертає (приватний, публічний) ключі сервера."""
    return _server_priv, _server_pub

def get_secretary_keys():
    """Повертає (приватний, публічний) ключі секретаря."""
    return _secretary_priv, _secretary_pub

