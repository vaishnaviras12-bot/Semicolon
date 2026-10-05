"""
Database Engine & Session Management
====================================
Provides SQLAlchemy relational database connection (PostgreSQL / SQLite fallback)
and MongoDB motor document store connection.
"""

import sys
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.app.config import settings

logger = logging.getLogger("ecdat.database")

# SQLAlchemy setup
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite"):
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
else:
    engine = create_engine(db_url, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# MongoDB setup (optional document store)
mongo_client = None
mongo_db = None

try:
    from pymongo import MongoClient
    mongo_client = MongoClient(settings.MONGODB_URL, serverSelectionTimeoutMS=1000)
    # Ping mongo to test connection
    mongo_client.admin.command('ping')
    mongo_db = mongo_client[settings.MONGODB_DATABASE]
    
    # Ensure required indexes exist on MongoDB collections
    mongo_db["users"].create_index("email", unique=True)
    mongo_db["scans"].create_index([("user_id", 1), ("created_at", -1)])
    mongo_db["scan_evidence"].create_index("scan_id")
    
    logger.info("Connected to MongoDB document store successfully and ensured indexes.")
except Exception as e:
    logger.info(f"MongoDB unavailable ({e}); utilizing relational DB JSON document store as fallback.")
    mongo_client = None
    mongo_db = None
