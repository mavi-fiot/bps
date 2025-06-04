#models/vote_record.py

from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class VoteRecord(Base):
    __tablename__ = "vote_records"

    id = Column(Integer, primary_key=True, index=True)
    voter_id = Column(String, nullable=False)
    choice = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    hash_plain = Column(String, nullable=False)
    hash_encrypted = Column(String, nullable=False)
    question_number = Column(Integer, nullable=False)
    decision_text = Column(String, nullable=False)
