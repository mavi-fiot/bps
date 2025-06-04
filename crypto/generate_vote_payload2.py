# crypto/generate_vote_payload2.py

from ecpy.curves import Curve
from hashlib import sha512

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# 🔐 Приватний ключ
priv_key = 6468757615581100091837520261682486743586164670420878291904123348470553542821
public_key = priv_key * G

# 📥 Вхідні дані
voter_id = "demo-voter"
ballot_id = "331ec1d6-529b-49fd-8816-fe8b283ba318"
choice = "за"
text = "Затвердити звіт за 2024 рік"
personalized = text + voter_id

# 📦 Хеш бюлетеня
h = sha512(personalized.encode()).digest()
hash_scalar = int.from_bytes(h, 'big') % q

# ✍️ Підпис: h * priv_key * G
signature = (hash_scalar * priv_key) * G

# 📤 Вивід
import json
payload = {
    "voter_id": voter_id,
    "ballot_id": ballot_id,
    "choice": choice,
    "signature": {
        "x": signature.x,
        "y": signature.y
    },
    "public_key": {
        "x": public_key.x,
        "y": public_key.y
    }
}
print(json.dumps(payload, indent=2))
