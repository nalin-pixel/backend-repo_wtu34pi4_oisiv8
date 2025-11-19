import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
from passlib.context import CryptContext

# Database helpers
from database import db, create_document, get_documents
from schemas import AuthUser

app = FastAPI(title="SaaS Landing API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --------- Models ---------
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    message: str
    user_id: Optional[str] = None
    plan: Optional[str] = None

# --------- Helpers ---------
COLL = "authuser"  # from AuthUser model name lowercased

def find_user_by_email(email: str):
    results = get_documents(COLL, {"email": email}, limit=1)
    return results[0] if results else None

# --------- Routes ---------
@app.get("/")
def read_root():
    return {"message": "SaaS Landing Backend Running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:60]}"
    return response

@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    if not db:
        raise HTTPException(status_code=500, detail="Database not configured")

    existing = find_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = pwd_context.hash(payload.password)
    doc = AuthUser(
        name=payload.name,
        email=payload.email,
        password_hash=password_hash,
        plan="free",
        is_verified=False,
    )
    user_id = create_document(COLL, doc)
    return {"message": "Signup successful", "user_id": user_id, "plan": "free"}

@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    if not db:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = find_user_by_email(payload.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify password
    if not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"message": "Login successful", "user_id": str(user.get("_id")), "plan": user.get("plan", "free")}

# Pricing list endpoint (could be dynamic later)
@app.get("/pricing")
def get_pricing():
    return {
        "plans": [
            {
                "name": "Free",
                "price": 0,
                "period": "mo",
                "features": [
                    "Basic analytics",
                    "Community support",
                    "Up to 3 projects"
                ]
            },
            {
                "name": "Pro",
                "price": 19,
                "period": "mo",
                "popular": True,
                "features": [
                    "Unlimited projects",
                    "Priority support",
                    "Team collaboration",
                    "API access"
                ]
            },
            {
                "name": "Business",
                "price": 49,
                "period": "mo",
                "features": [
                    "SSO & SAML",
                    "Custom roles",
                    "Audit logs",
                    "Dedicated support"
                ]
            }
        ]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
