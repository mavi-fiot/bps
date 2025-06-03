#crypto/hash_util.py

from ecpy.curves import Curve, Point
import secrets
import hashlib

# Вибір кривої (найближча до специфікацій ДСТУ 9041:2020 — Ed25519)
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

print(f"📀 Крива: {curve.name}")
print(f"🔢 Порядок q = {q}")

# Генерація ключів
priv_key = secrets.randbelow(q)
pub_key = priv_key * G

print(f"🔐 Приватний ключ: {priv_key}")
print(f"🔑 Публічний ключ: ({pub_key.x}, {pub_key.y})")

# Повідомлення
message = 'З питання першого порядку денного за проектом рішення: Затвердити річний звіт Товариства за 2024 рік - голосую За'
print(f"\n📨 Повідомлення: {message}")

# Хеш повідомлення → скаляр → точка
hash_scalar = int.from_bytes(hashlib.sha512(message.encode()).digest(), 'big') % q
M = hash_scalar * G
print(f"🔢 Хеш як скаляр: {hash_scalar}")
print(f"📍 Повідомлення як точка M: ({M.x}, {M.y})")

# Шифрування (ElGamal)
r = secrets.randbelow(q)
C1 = r * G
C2 = M + r * pub_key

print(f"\n🔐 Шифрування ElGamal:")
print(f"• C1 = r * G = ({C1.x}, {C1.y})")
print(f"• C2 = M + r * B = ({C2.x}, {C2.y})")

# Розшифрування
S = priv_key * C1
M_decrypted = C2 - S

print(f"\n📥 Розшифровано точку M: ({M_decrypted.x}, {M_decrypted.y})")

# Перевірка відповідності
M_check = hash_scalar * G
is_valid = M_check == M_decrypted
print(f"\n✅ Перевірка відповідності: {'успішна' if is_valid else '❌ неуспішна'}")

# === crypto/hash_util.py ===
# Файл для обчислення хешу бюлетеня

def hash_ballot(ballot_text: str) -> int:
    h = hashlib.sha512(ballot_text.encode()).digest()
    return int.from_bytes(h, 'big') % q

# === crypto/signature.py ===
# Підпис бюлетеня сервером або секретарем

def sign_hash(hash_scalar: int, private_key: int) -> Point:
    return private_key * G

# Перевірка підпису за публічним ключем

def verify_signature(hash_scalar: int, signature: Point, public_key: Point) -> bool:
    expected = hash_scalar * G
    return signature == expected
