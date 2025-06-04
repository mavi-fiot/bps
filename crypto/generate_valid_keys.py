# crypto/generate_valid_keys.py

from ecpy.curves import Curve
import secrets

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

priv_key = secrets.randbelow(q)
pub_key = priv_key * G

print("✅ Публічний ключ (точка на кривій):")
print(f"x: {pub_key.x}")
print(f"y: {pub_key.y}")

print("\n🔐 Приватний ключ:")
print(f"{priv_key}")
