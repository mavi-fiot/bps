#kzp/encryption_service.py

from ecpy.curves import Curve, Point
import secrets

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

def elgamal_encrypt(M: Point, pub_key: Point):
    r = secrets.randbelow(q)
    C1 = r * G
    C2 = M + r * pub_key
    return C1, C2

def elgamal_decrypt(C1: Point, C2: Point, priv_key: int):
    return C2 - priv_key * C1
