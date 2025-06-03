# kzp/secure_vote_api.py

from fastapi import APIRouter
from ecpy.curves import Curve, Point
import hashlib, secrets

router = APIRouter()

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

@router.get("/test")
def demo_crypto():
    # Генерація ключів
    priv_key = secrets.randbelow(q)
    pub_key = priv_key * G

    # Повідомлення
    message = "З питання першого порядку денного — голосую За"
    hash_scalar = int.from_bytes(hashlib.sha512(message.encode()).digest(), 'big') % q
    M = hash_scalar * G

    # ElGamal-шифрування
    r = secrets.randbelow(q)
    C1 = r * G
    C2 = M + r * pub_key

    # Розшифрування
    S = priv_key * C1
    M_decrypted = C2 - S
    M_check = hash_scalar * G
    is_valid = M_check == M_decrypted

    return {
        "curve": curve.name,
        "private_key": priv_key,
        "public_key": {"x": pub_key.x, "y": pub_key.y},
        "message": message,
        "hash_scalar": hash_scalar,
        "point_M": {"x": M.x, "y": M.y},
        "ciphertext": {
            "C1": {"x": C1.x, "y": C1.y},
            "C2": {"x": C2.x, "y": C2.y},
        },
        "decrypted_point_M": {"x": M_decrypted.x, "y": M_decrypted.y},
        "valid": is_valid
    }
