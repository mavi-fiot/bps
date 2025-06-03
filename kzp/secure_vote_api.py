# kzp/secure_vote_api.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ecpy.curves import Curve, Point
import hashlib, secrets
from kzp.store import BallotStorage


# Ініціалізація кривої та генератора
curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order  # 👈 Тільки тут q стає доступним

# Після q — ключі:
server_priv = secrets.randbelow(q)
server_pub = server_priv * G

secretary_priv = secrets.randbelow(q)
secretary_pub = secretary_priv * G

router = APIRouter()

curve = Curve.get_curve('Ed25519')
G = curve.generator
q = curve.order

storage = BallotStorage()  # ← має бути вже ініціалізовано

class SignaturePoint(BaseModel):
    x: int
    y: int

class VoteIn(BaseModel):
    voter_id: str
    ballot_id: str
    choice: str
    signature: SignaturePoint
    public_key: SignaturePoint  # публічний ключ виборця

@router.post("/vote")
def submit_vote(vote: VoteIn):
    ballot = storage.get_ballot(vote.ballot_id)
    if not ballot:
        raise HTTPException(status_code=404, detail="Бюлетень не знайдено")

    if vote.choice not in ["за", "проти"]:
        raise HTTPException(status_code=400, detail="Недопустимий вибір")

    # Хеш вибору
    hash_scalar = int.from_bytes(hashlib.sha512(vote.choice.encode()).digest(), 'big') % q
    expected_point = hash_scalar * G

    # Підпис, публічний ключ
    signature = Point(vote.signature.x, vote.signature.y, curve)
    public_key = Point(vote.public_key.x, vote.public_key.y, curve)

    # Перевірка: чи підпис == h * G (на рівні точки)
    is_valid = signature == expected_point

    if not is_valid:
        raise HTTPException(status_code=403, detail="❌ Підпис недійсний")

    # Зберігаємо голос (хеш + підпис)
    storage.store_encrypted(vote.voter_id, {
        "ballot_id": vote.ballot_id,
        "choice": vote.choice,
        "hash_scalar": hash_scalar,
        "signature": signature,
        "public_key": public_key
    })

    return {
        "status": "✅ Голос збережено",
        "voter_id": vote.voter_id,
        "choice": vote.choice,
        "valid_signature": is_valid
    }

@router.post("/finalize_vote")
def finalize_vote():
    results = {}
    ballots = storage.ballots
    votes = storage.get_all_votes()

    for voter_id, vote_data in votes.items():
        ballot_id = vote_data["ballot_id"]
        ballot = ballots.get(ballot_id)

        if not ballot:
            results[voter_id] = "❌ Бюлетень не знайдено"
            continue

        # Розшифрування: спочатку секретар
        C1_sec = ballot["C1_sec"]
        C2_sec = ballot["C2_sec"]
        C2_srv = C2_sec - secretary_priv * C1_sec  # зняти шифр секретаря

        # Тепер сервер
        C1_srv = ballot["C1_srv"]
        M = C2_srv - server_priv * C1_srv          # зняти шифр сервера

        # Перевірка хешу
        expected_point = vote_data["hash_scalar"] * G
        if M != expected_point:
            results[voter_id] = "❌ Хеш не збігається"
            continue

        # Перевірка підпису (ще раз, для надійності)
        signature = vote_data["signature"]
        public_key = vote_data["public_key"]
        if signature != vote_data["hash_scalar"] * G:
            results[voter_id] = "❌ Невірний підпис"
            continue

        # Голос зараховується
        results[voter_id] = f"✅ Голос зараховано: {vote_data['choice']}"

    return results
