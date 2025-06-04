#crypto.generate_valid_vote

from ecpy.curves import Curve, Point
from crypto.hash_util import hash_ballot
from crypto.signature import sign_hash
import secrets
import json

curve = Curve.get_curve("Ed25519")
G = curve.generator
q = curve.order

# 🔐 Приватний ключ
priv = secrets.randbelow(q)
pub = priv * G

# 🗳️ Текст + ID
voter_id = "demo-voter"
ballot_text = "Затвердити звіт за 2024 рік"
personalized = ballot_text + voter_id
hash_scalar = hash_ballot(personalized)

# ✍️ Підпис
signature = sign_hash(hash_scalar, priv) 

# 🟢 Підготовка JSON
payload = {
    "voter_id": voter_id,
    "ballot_id": "c1d8c64e-b2a8-407d-9afd-ddfa0d867797",
    "choice": "за",
    "signature": {"x": signature.x, "y": signature.y},
    "public_key": {"x": pub.x, "y": pub.y}
}

print(json.dumps(payload, indent=2))
