# kzp/secure_vote_api.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ecpy.curves import Point

from kzp.store import BallotStorage
from db.database import SessionLocal
from services.vote_storage import save_vote
from kzp.crypto_logic import get_curve_params, get_server_keys, get_secretary_keys
from crypto.hash_util import hash_ballot
from crypto.encryption import encrypt_hash, decrypt_ciphertext, verify_decrypted_point
from crypto.signature import verify_signature
from models.crypto_schemas import (
    VoteIn,
    PointData,
    EncryptedData,
    EncryptDemoResponse,
    DecryptDemoResponse,  
)
# import hashlib
import uuid

# 🔐 Криптопараметри
curve, G, q = get_curve_params()
server_priv, server_pub = get_server_keys()
secretary_priv, secretary_pub = get_secretary_keys()

router = APIRouter()
storage = BallotStorage()

# 📦 Pydantic моделі
class SignaturePoint(BaseModel):
    x: int
    y: int

class VoteIn(BaseModel):
    voter_id: str
    ballot_id: str
    choice: str
    signature: SignaturePoint
    public_key: SignaturePoint

class EncryptedData(BaseModel):
    C1_srv: tuple[int, int]
    C2_srv: tuple[int, int]
    C1_sec: tuple[int, int]
    C2_sec: tuple[int, int]
    expected_hash_scalar: int

def parse_point(data: dict) -> Point:
    try:
        x = int(float(data["x"]))
        y = int(float(data["y"]))
        return Point(x, y, curve)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"❌ Некоректна точка: {e}")


# ==================== 🗳️ Генерація бюлетенів ====================
@router.post("/generate_ballots")
def generate_ballots():
    text = "Затвердити звіт за 2024 рік"
    base_question = "Питання перше – Про затвердження звіту за 2024 рік"
    variants = ["за", "проти", "утримався"]
    ballot_ids = {}

    for variant in variants:
        ballot_id = str(uuid.uuid4())
        ballot_ids[variant] = ballot_id

        storage.save_ballot(ballot_id, {
            "text": text,
            "variant": variant
        })

    return {
        "question": base_question,
        "decision": text,
        "ballots": ballot_ids
    }

# ==================== ✅ Голосування ====================
@router.post("/vote")
def submit_vote(vote: VoteIn):
    ballot = storage.get_ballot(vote.ballot_id)
    if not ballot:
        raise HTTPException(status_code=404, detail="Бюлетень не знайдено")

    try:
        signature = parse_point(vote.signature.model_dump())
        public_key = parse_point(vote.public_key.model_dump())
    except Exception:
        raise HTTPException(status_code=400, detail="❌ Недійсні координати підпису або публічного ключа (не належать кривій)")

    # 🎯 Формування персоналізованого хешу
    personalized = ballot["text"] + vote.voter_id
    hash_scalar = hash_ballot(personalized)

    # ✅ Перевірка підпису
    if not verify_signature(hash_scalar, signature, public_key):
        raise HTTPException(status_code=403, detail="❌ Недійсний підпис")

    # 🔐 Шифрування хешу
    C1_srv, C2_srv = encrypt_hash(hash_scalar, server_pub)
    C1_sec, C2_sec = encrypt_hash(hash_scalar, secretary_pub)

    storage.store_encrypted(vote.voter_id, {
        "ballot_id": vote.ballot_id,
        "choice": vote.choice,
        "hash_scalar": hash_scalar,
        "signature": signature,
        "public_key": public_key,
        "C1_srv": C1_srv,
        "C2_srv": C2_srv,
        "C1_sec": C1_sec,
        "C2_sec": C2_sec,
        "original_text": ballot["text"]
    })

    db = SessionLocal()
    try:
        save_vote(
            db=db,
            voter_id=vote.voter_id,
            choice=vote.choice,
            hash_plain=str(hash_scalar),
            hash_encrypted=f"{C2_sec.x},{C2_sec.y}",
            question_number=1,
            decision_text=ballot["text"]
        )
    finally:
        db.close()

    return {
        "status": "✅ Голос зашифровано та збережено",
        "voter_id": vote.voter_id,
        "choice": vote.choice,
        "valid_signature": True
    }


# ==================== 🛑 Завершення голосування ====================
@router.post("/finalize_vote")
def finalize_vote():
    results = {}
    votes = storage.get_all_votes()

    for voter_id, vote_data in votes.items():
        try:
            M1 = decrypt_ciphertext(vote_data["C1_sec"], vote_data["C2_sec"], secretary_priv)
            M_final = decrypt_ciphertext(vote_data["C1_srv"], M1, server_priv)

            if not verify_decrypted_point(M_final, vote_data["hash_scalar"]):
                results[voter_id] = "❌ Хеш не збігається"
                continue

            if vote_data["signature"] != vote_data["hash_scalar"] * G:
                results[voter_id] = "❌ Підпис недійсний"
                continue

            results[voter_id] = f"✅ Голос враховано: {vote_data['choice']}"

        except Exception as e:
            results[voter_id] = f"❌ Помилка: {str(e)}"

    return results

# ==================== 🔍 Тест шифрування та розшифрування ====================
TEST_MESSAGE = "Голосую за затвердження звіту за 2024 рік"

@router.get("/encrypt_demo", response_model=EncryptDemoResponse)
def encrypt_demo():
    hash_scalar = hash_ballot(TEST_MESSAGE)
    M = hash_scalar * G
    C1_srv, C2_srv = encrypt_hash(hash_scalar, server_pub)
    C1_sec, C2_sec = encrypt_hash(hash_scalar, secretary_pub)

    return EncryptDemoResponse(
        message=TEST_MESSAGE,
        hash_scalar=hash_scalar,
        point_M={"x": M.x, "y": M.y},
        server_public_key={"x": server_pub.x, "y": server_pub.y},
        secretary_public_key={"x": secretary_pub.x, "y": secretary_pub.y},
        C1_srv={"x": C1_srv.x, "y": C1_srv.y},
        C2_srv={"x": C2_srv.x, "y": C2_srv.y},
        C1_sec={"x": C1_sec.x, "y": C1_sec.y},
        C2_sec={"x": C2_sec.x, "y": C2_sec.y}
    )

@router.post("/decrypt_demo")
def decrypt_demo(data: EncryptedData):
    C1_srv = Point(*data.C1_srv, curve)
    C2_srv = Point(*data.C2_srv, curve)
    C1_sec = Point(*data.C1_sec, curve)
    C2_sec = Point(*data.C2_sec, curve)

    M1 = decrypt_ciphertext(C1_sec, C2_sec, secretary_priv)
    M_final = decrypt_ciphertext(C1_srv, M1, server_priv)
    expected = data.expected_hash_scalar * G

    return {
        "decrypted_point": {"x": M_final.x, "y": M_final.y},
        "expected_point": {"x": expected.x, "y": expected.y},
        "valid": M_final == expected
    }
