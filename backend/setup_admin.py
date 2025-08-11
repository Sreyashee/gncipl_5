import os
from pymongo import MongoClient
from passlib.hash import bcrypt  # Use bcrypt, not bcrypt_sha256
from dotenv import load_dotenv

load_dotenv()
MONGO_URI = os.environ['MONGO_URI']
client = MongoClient(MONGO_URI)
db = client.get_default_database()
admins = db.admins

username = input("Admin username: ").strip()
password = input("Admin password: ").strip()

# Optional: check if user already exists
if admins.find_one({"username": username}):
    print(f"Admin with username '{username}' already exists.")
else:
    hashed = bcrypt.hash(password)
    res = admins.insert_one({"username": username, "password": hashed})
    print("Admin created:", res.inserted_id)
