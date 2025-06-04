# crypto/generate_vote_payload3.py
from ecpy.curves import Curve, Point
from crypto.hash_util import hash_ballot
from crypto.signature import sign_hash
import json

# Крива
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

# 🔐 Твій приватний ключ (той, що використовувався для генерації пари ключів)
priv_key = 6468757615581100091837520261682486743586164670420878291904123348470553542821
pub_key = priv_key * G

# Дані бюлетеня
ballot_text = "Затвердити звіт за 2024 рік"
voter_id = "demo-voter"
ballot_id = "c1d8c64e-b2a8-407d-9afd-ddfa0d867797"
choice = "за"

# Підпис
personalized = ballot_text + voter_id
hash_scalar = hash_ballot(personalized)
signature = sign_hash(hash_scalar, priv_key)

payload = {
    "voter_id": voter_id,
    "ballot_id": ballot_id,
    "choice": choice,
    "signature": {"x": signature.x, "y": signature.y},
    "public_key": {"x": pub_key.x, "y": pub_key.y}
}

print(json.dumps(payload, indent=2))
