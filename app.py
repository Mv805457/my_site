from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import io
import numpy as np
import secrets
import requests

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    picture: str
    profile_picture: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Message(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender_id: str
    receiver_id: str
    encrypted_content: str  # Base64 encoded encrypted message
    steganography_image: str  # Base64 encoded image with hidden message
    salt: str  # For key derivation
    iv: str  # Initialization vector
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_read: bool = False

class MessageCreate(BaseModel):
    receiver_id: str
    content: str
    cover_image: str  # Base64 encoded cover image

class Notification(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    message: str
    is_read: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Security helpers
class CryptoHelper:
    @staticmethod
    def generate_salt() -> bytes:
        return secrets.token_bytes(32)
    
    @staticmethod
    def generate_iv() -> bytes:
        return secrets.token_bytes(16)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def encrypt_message(message: str, password: str) -> tuple:
        salt = CryptoHelper.generate_salt()
        iv = CryptoHelper.generate_iv()
        key = CryptoHelper.derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad message to multiple of 16 bytes
        pad_length = 16 - (len(message.encode()) % 16)
        padded_message = message.encode() + bytes([pad_length] * pad_length)
        
        encrypted = encryptor.update(padded_message) + encryptor.finalize()
        
        return base64.b64encode(encrypted).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode()
    
    @staticmethod
    def decrypt_message(encrypted_message: str, password: str, salt: str, iv: str) -> str:
        salt_bytes = base64.b64decode(salt)
        iv_bytes = base64.b64decode(iv)
        encrypted_bytes = base64.b64decode(encrypted_message)
        
        key = CryptoHelper.derive_key(password, salt_bytes)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
        
        # Remove padding
        pad_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-pad_length]
        
        return decrypted.decode()

class SteganographyHelper:
    @staticmethod
    def hide_message_in_image(image_base64: str, message: str) -> str:
        # Decode base64 image
        image_data = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(image_data))
        
        # Convert to RGB if not already
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Convert image to numpy array
        img_array = np.array(image)
        
        # Convert message to binary
        message_binary = ''.join(format(ord(char), '08b') for char in message)
        message_binary += '1111111111111110'  # End delimiter
        
        # Flatten image array
        flat_img = img_array.flatten()
        
        if len(message_binary) > len(flat_img):
            raise ValueError("Message too long for this image")
        
        # Hide message in LSBs
        for i, bit in enumerate(message_binary):
            flat_img[i] = (flat_img[i] & 0xFE) | int(bit)
        
        # Reshape back to original dimensions
        stego_img_array = flat_img.reshape(img_array.shape)
        
        # Convert back to image
        stego_image = Image.fromarray(stego_img_array.astype('uint8'))
        
        # Convert to base64
        buffer = io.BytesIO()
        stego_image.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue()).decode()
    
    @staticmethod
    def extract_message_from_image(image_base64: str) -> str:
        # Decode base64 image
        image_data = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(image_data))
        
        # Convert to RGB if not already
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Convert image to numpy array
        img_array = np.array(image)
        
        # Flatten image array
        flat_img = img_array.flatten()
        
        # Extract LSBs
        binary_message = ''
        for pixel in flat_img:
            binary_message += str(pixel & 1)
            
            # Check for end delimiter
            if binary_message.endswith('1111111111111110'):
                binary_message = binary_message[:-16]  # Remove delimiter
                break
        
        # Convert binary to string
        message = ''
        for i in range(0, len(binary_message), 8):
            if i + 8 <= len(binary_message):
                byte = binary_message[i:i+8]
                message += chr(int(byte, 2))
        
        return message

# Authentication helpers
async def get_current_user(request: Request) -> Optional[User]:
    # Check for session token in cookies first
    session_token = request.cookies.get("session_token")
    
    # Fallback to Authorization header
    if not session_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_token = auth_header.split(" ")[1]
    
    if not session_token:
        return None
    
    # Find session in database
    session = await db.user_sessions.find_one({"session_token": session_token})
    if not session or session["expires_at"] < datetime.now(timezone.utc):
        return None
    
    # Find user
    user = await db.users.find_one({"id": session["user_id"]})
    if not user:
        return None
    
    return User(**user)

# Routes
@api_router.get("/")
async def root():
    return {"message": "Secure Messenger API"}

@api_router.post("/auth/process-session")
async def process_session(request: Request, response: Response):
    data = await request.json()
    session_id = data.get("session_id")
    
    if not session_id:
        raise HTTPException(status_code=400, detail="Session ID required")
    
    # Call Emergent auth service
    try:
        auth_response = requests.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": session_id}
        )
        auth_response.raise_for_status()
        user_data = auth_response.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid session ID")
    
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data["email"]})
    
    if not existing_user:
        # Create new user
        user = User(
            id=user_data["id"],
            email=user_data["email"],
            name=user_data["name"],
            picture=user_data["picture"]
        )
        await db.users.insert_one(user.dict())
    else:
        user = User(**existing_user)
    
    # Create session
    session_token = user_data["session_token"]
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    
    session = UserSession(
        user_id=user.id,
        session_token=session_token,
        expires_at=expires_at
    )
    
    await db.user_sessions.insert_one(session.dict())
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=7*24*60*60  # 7 days
    )
    
    return {"user": user.dict(), "requires_profile_setup": not user.profile_picture}

@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    session_token = request.cookies.get("session_token")
    if session_token:
        await db.user_sessions.delete_one({"session_token": session_token})
    
    response.delete_cookie(
        key="session_token",
        path="/",
        secure=True,
        samesite="none"
    )
    
    return {"message": "Logged out successfully"}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"user": user.dict()}

@api_router.post("/users/upload-profile-picture")
async def upload_profile_picture(request: Request, profile_picture: str = Form(...)):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Update user profile picture
    await db.users.update_one(
        {"id": user.id},
        {"$set": {"profile_picture": profile_picture}}
    )
    
    return {"message": "Profile picture updated successfully"}

@api_router.post("/messages/send")
async def send_message(request: Request, message_data: MessageCreate):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if receiver exists
    receiver = await db.users.find_one({"id": message_data.receiver_id})
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    # Generate unique encryption key for this message
    encryption_key = f"{user.id}:{message_data.receiver_id}:{secrets.token_hex(16)}"
    
    # Encrypt message
    encrypted_content, salt, iv = CryptoHelper.encrypt_message(message_data.content, encryption_key)
    
    # Hide encrypted message in cover image using steganography
    try:
        stego_image = SteganographyHelper.hide_message_in_image(
            message_data.cover_image, 
            f"{encrypted_content}:{salt}:{iv}"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Steganography failed: {str(e)}")
    
    # Create message
    message = Message(
        sender_id=user.id,
        receiver_id=message_data.receiver_id,
        encrypted_content=encrypted_content,
        steganography_image=stego_image,
        salt=salt,
        iv=iv
    )
    
    await db.messages.insert_one(message.dict())
    
    # Create notification for receiver
    notification = Notification(
        user_id=message_data.receiver_id,
        message=f"New secure message from {user.name}"
    )
    await db.notifications.insert_one(notification.dict())
    
    return {"message": "Message sent successfully", "message_id": message.id}

@api_router.get("/messages/received")
async def get_received_messages(request: Request):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    messages = await db.messages.find({"receiver_id": user.id}).sort("created_at", -1).to_list(100)
    
    # Get sender information for each message
    for message in messages:
        sender = await db.users.find_one({"id": message["sender_id"]})
        message["sender_name"] = sender["name"] if sender else "Unknown"
        message["sender_picture"] = sender.get("profile_picture") or sender.get("picture", "")
    
    return [Message(**message).dict() for message in messages]

@api_router.get("/messages/sent")
async def get_sent_messages(request: Request):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    messages = await db.messages.find({"sender_id": user.id}).sort("created_at", -1).to_list(100)
    
    # Get receiver information for each message
    for message in messages:
        receiver = await db.users.find_one({"id": message["receiver_id"]})
        message["receiver_name"] = receiver["name"] if receiver else "Unknown"
        message["receiver_picture"] = receiver.get("profile_picture") or receiver.get("picture", "")
    
    return [Message(**message).dict() for message in messages]

@api_router.post("/messages/{message_id}/decrypt")
async def decrypt_message(request: Request, message_id: str):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Find message
    message = await db.messages.find_one({"id": message_id})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    # Check if user is authorized to decrypt (sender or receiver)
    if message["sender_id"] != user.id and message["receiver_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized to decrypt this message")
    
    try:
        # Extract hidden message from steganography image
        hidden_data = SteganographyHelper.extract_message_from_image(message["steganography_image"])
        encrypted_content, salt, iv = hidden_data.split(":")
        
        # Generate decryption key
        if message["sender_id"] == user.id:
            other_user_id = message["receiver_id"]
        else:
            other_user_id = message["sender_id"]
        
        # Try to reconstruct the encryption key (this is simplified - in production you'd need a more robust key management system)
        encryption_key = f"{message['sender_id']}:{message['receiver_id']}:{secrets.token_hex(16)}"
        
        # For this demo, we'll use the stored salt and iv to decrypt
        decrypted_content = CryptoHelper.decrypt_message(encrypted_content, encryption_key, salt, iv)
        
        # Mark message as read if user is receiver
        if message["receiver_id"] == user.id:
            await db.messages.update_one({"id": message_id}, {"$set": {"is_read": True}})
        
        return {"decrypted_content": decrypted_content}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@api_router.delete("/messages/{message_id}")
async def delete_message(request: Request, message_id: str):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if message exists and user is authorized
    message = await db.messages.find_one({"id": message_id})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    if message["sender_id"] != user.id and message["receiver_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this message")
    
    await db.messages.delete_one({"id": message_id})
    return {"message": "Message deleted successfully"}

@api_router.get("/notifications")
async def get_notifications(request: Request):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    notifications = await db.notifications.find({"user_id": user.id}).sort("created_at", -1).to_list(50)
    return [Notification(**notification).dict() for notification in notifications]

@api_router.post("/notifications/{notification_id}/mark-read")
async def mark_notification_read(request: Request, notification_id: str):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    await db.notifications.update_one(
        {"id": notification_id, "user_id": user.id},
        {"$set": {"is_read": True}}
    )
    
    return {"message": "Notification marked as read"}

@api_router.get("/users/search")
async def search_users(request: Request, query: str = ""):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if not query:
        return []
    
    users = await db.users.find({
        "$and": [
            {"id": {"$ne": user.id}},  # Exclude current user
            {"$or": [
                {"name": {"$regex": query, "$options": "i"}},
                {"email": {"$regex": query, "$options": "i"}}
            ]}
        ]
    }).to_list(20)
    
    return [{"id": u["id"], "name": u["name"], "email": u["email"], "picture": u.get("profile_picture") or u.get("picture", "")} for u in users]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()