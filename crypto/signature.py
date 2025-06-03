# === crypto/signature.py ===
# Підпис хешу та перевірка підпису на основі кривих Едвардса (Ed25519)

from ecpy.curves import Curve, Point

# Вибір кривої Ed25519 (відповідає специфікації ДСТУ 9041)
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Підпис хешу (як скалярного значення): повертається точка на кривій

def sign_hash(hash_scalar: int, private_key: int) -> Point:
    return hash_scalar * (private_key * G)

# Перевірка підпису за публічним ключем

def verify_signature(hash_scalar: int, signature: Point, public_key: Point) -> bool:
    expected = hash_scalar * public_key
    return signature == expected
