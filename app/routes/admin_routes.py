#app/routes/admin_routes.py

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from db.database import SessionLocal
from models.vote_record import VoteRecord
from models.vote_record import VoteRecordOut
from kzp.secure_vote_api import router as secure_vote_router

router = APIRouter()

# Підключення до БД
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# @router.get("/admin/votes")
# def get_all_votes(db: Session = Depends(get_db)):
#     votes = db.query(VoteRecord).all()
#     return [
#         {
#             "voter_id": v.voter_id,
#             "choice": v.choice,
#             "timestamp": v.timestamp.isoformat(),
#             "hash_plain": v.hash_plain,
#             "hash_encrypted": v.hash_encrypted,
#             "question_number": v.question_number,
#             "decision_text": v.decision_text
#         } for v in votes
#     ]

@router.get("/admin/votes", response_model=list[VoteRecordOut])
def get_all_votes(db: Session = Depends(get_db)):
    return db.query(VoteRecord).all()