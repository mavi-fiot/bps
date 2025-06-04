#python -m crypto.generate_valid_vote2

from ecpy.curves import Curve, Point
import secrets
import json
from hashlib import sha3_256

# Налаштування
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# Вхідні дані
voter_id = "demo-voter"
ballot_text = "Затвердити звіт за 2024 рік"
personalized = ballot_text + voter_id

# Генерація ключів
priv = secrets.randbelow(q)
pub = priv * G

# Хешування
def hash_ballot(text: str) -> int:
    digest = sha3_256(text.encode("utf-8")).digest()
    return int.from_bytes(digest, byteorder="big") % q

hash_scalar = hash_ballot(personalized)
M = hash_scalar * G  # Представлення як точка

# Підпис (демо)
signature = priv * G

# Виведення JSON для API
payload = {
    "voter_id": voter_id,
    "ballot_id": "🔻СЮДИ ВСТАВ ID З /generate_ballots",
    "choice": "за",
    "signature": {
        "x": signature.x,
        "y": signature.y
    },
    "public_key": {
        "x": pub.x,
        "y": pub.y
    }
}

print(json.dumps(payload, indent=2))

