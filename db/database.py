# db/database.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.vote_record import Base

SQLALCHEMY_DATABASE_URL = "sqlite:///./votes.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Створення таблиць, якщо не існують
def init_db():
    Base.metadata.create_all(bind=engine)
