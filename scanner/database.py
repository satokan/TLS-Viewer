from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

# Default to SQLite for development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/scanner.db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
