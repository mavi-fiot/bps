# === crypto/signature.py ===
# Підпис хешу та перевірка підпису на основі кривих Едвардса (Ed25519)

from ecpy.curves import Curve, Point

# Вибір кривої Ed25519 (відповідає специфікації ДСТУ 9041)
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Підпис хешу (як скалярного значення): повертається точка на кривій

# def sign_hash(hash_scalar: int, private_key: int) -> Point:
#     return hash_scalar * (private_key * G)
def sign_hash(hash_scalar: int, private_key: int) -> Point:
    public_key = private_key * G
    print(f"Значення G: {G}")
    print(f"  Публічний ключ: ({public_key.x}, {public_key.y})")
    print(f"  Хеш (скаляр): {hash_scalar}")
    signed_point = hash_scalar * public_key
    print(f"  Підпис (точка): ({signed_point.x}, {signed_point.y})")
    return signed_point


# Перевірка підпису за публічним ключем

# def verify_signature(hash_scalar: int, signature: Point, public_key: Point) -> bool:
#     expected = hash_scalar * public_key
#     print(f"Відтворення точки (контроль)): ({expected.x}, {expected.y})")

def verify_signature(hash_scalar: int, signature: Point, public_key: Point) -> bool:
    expected = hash_scalar * public_key
    print(f"\n _________Контроль на сервері:")
    print(f"  Публічний ключ: ({public_key.x}, {public_key.y})")
    print(f"  Хеш: {hash_scalar}")
    print(f"  Очікувана точка: ({expected.x}, {expected.y})")
    print(f"  Відтворення точки (контроль)): ({expected.x}, {expected.y})")
    print(f"  Підпис: ({signature.x}, {signature.y})")
    return signature == expected


if __name__ == "__main__":
    import secrets

    voter_id = "dv1"
    ballot_text = "Затвердити звіт за 2024 рік"
    personalized = ballot_text + voter_id

    def hash_ballot(text: str) -> int:
        from hashlib import sha3_256
        digest = sha3_256(text.encode("utf-8")).digest()
        return int.from_bytes(digest, byteorder="big") % q

    priv = secrets.randbelow(q)
    pub = priv * G
    hash_scalar = hash_ballot(personalized)

    signature = sign_hash(hash_scalar, priv)
    print(f"\n✅ Контроль відповідності підпису:")
    if verify_signature(hash_scalar, signature, pub):
        print("✅ Підпис підтверджено")
    else:
        print("❌ Підпис НЕПРАВИЛЬНИЙ")
