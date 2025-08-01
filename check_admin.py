# check_admin.py
import asyncio
from database import init_db
from models import User

async def check_admin():
    await init_db()
    
    # Find all users
    users = await User.find_all().to_list()
    
    print(f"Total users in database: {len(users)}")
    for user in users:
        print(f"Email: {user.email}")
        print(f"Is Admin: {user.is_admin}")
        print(f"Is Active: {user.is_active}")
        print("---")

if __name__ == "__main__":
    asyncio.run(check_admin())
