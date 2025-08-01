# database.py
import os
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient
from models import User, Resume
from dotenv import load_dotenv

load_dotenv()

async def init_db():
    # MongoDB connection
    MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    DATABASE_NAME = os.getenv("DATABASE_NAME", "portfolio")
    
    # Create Motor client
    client = AsyncIOMotorClient(MONGODB_URL)
    
    # Initialize beanie with the User model
    await init_beanie(database=client[DATABASE_NAME], document_models=[User, Resume])
    
    
    print(f"Connected to MongoDB: {DATABASE_NAME}")


#for resume
