from ecpy.curves import Curve, Point
from hashlib import sha512
import secrets
import json

# 1. Параметри кривої
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# 2. Дані
text = "Затвердити звіт за 2024 рік"
voter_id = "demo-voter"
personalized = text + voter_id

# 3. Генерація ключів виборця
priv_key = secrets.randbelow(q)
pub_key = priv_key * G

# 4. Обчислення хешу
hash_scalar = int.from_bytes(sha512(personalized.encode()).digest(), 'big') % q

# 5. Підпис (для демонстрації — просте множення, як у verify_signature)
signature = priv_key * G

# 6. Формування JSON-запиту
json_payload = {
    "voter_id": voter_id,
    "ballot_id": "СЮДИ ВСТАВ ID БЮЛЕТЕНЯ",  # ← заміни вручну
    "choice": "за",
    "signature": {
        "x": signature.x,
        "y": signature.y
    },
    "public_key": {
        "x": pub_key.x,
        "y": pub_key.y
    }
}

# 7. Вивід JSON-запиту
print(json.dumps(json_payload, indent=2))
