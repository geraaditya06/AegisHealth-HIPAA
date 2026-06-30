from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
import bcrypt
import os
import requests
from jose import jwt
from datetime import datetime, timedelta
from db import get_connection
from core.audit import (
    record_action,
    ACTION_LOGIN,
    ACTION_LOGOUT,
    ACTION_REGISTER,
    ACTION_GOOGLE_LOGIN,
)
from core.security import CurrentUser, get_current_user

router = APIRouter()

SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440))

class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str


class GoogleLoginRequest(BaseModel):
    credential: str

def create_token(user_id: int, email: str, role: str):
    expire = datetime.utcnow() + timedelta(minutes=EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "email": email, "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_or_create_google_user(email: str, google_sub: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, email, role FROM users WHERE email = ? OR google_sub = ?",
        (email, google_sub)
    )
    user = cur.fetchone()

    if user:
        cur.execute(
            "UPDATE users SET google_sub = ?, auth_provider = 'google' WHERE id = ?",
            (google_sub, user[0])
        )
        conn.commit()
        cur.execute("SELECT id, email, role FROM users WHERE id = ?", (user[0],))
        saved_user = cur.fetchone()
        cur.close()
        conn.close()
        return saved_user

    placeholder_hash = bcrypt.hashpw(os.urandom(24), bcrypt.gensalt()).decode()
    cur.execute(
        "INSERT INTO users (email, password_hash, auth_provider, google_sub) VALUES (?, ?, 'google', ?)",
        (email, placeholder_hash, google_sub)
    )
    conn.commit()
    user_id = cur.lastrowid
    cur.execute("SELECT id, email, role FROM users WHERE id = ?", (user_id,))
    saved_user = cur.fetchone()
    cur.close()
    conn.close()
    return saved_user

def log_action(user_id, action, resource, ip):
    """Backward-compatible audit helper.

    Delegates to :func:`core.audit.record_action`. New code should call
    ``record_action`` directly with the ``request`` to also capture the browser
    user-agent and organization.
    """
    record_action(user_id, action, resource, ip_address=ip)

@router.post("/register")
def register(req: RegisterRequest, request: Request):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (req.email,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    cur.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (req.email, hashed)
    )
    conn.commit()
    user_id = cur.lastrowid
    cur.execute("SELECT id, role FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    token = create_token(user[0], req.email, user[1])
    record_action(user[0], ACTION_REGISTER, "users", request=request)
    return {"token": token, "email": req.email, "role": user[1]}

@router.post("/login")
def login(req: LoginRequest, request: Request):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, role FROM users WHERE email = ?", (req.email,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user or not bcrypt.checkpw(req.password.encode(), user[1].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user[0], req.email, user[2])
    record_action(user[0], ACTION_LOGIN, "users", request=request)
    return {"token": token, "email": req.email, "role": user[2]}


@router.post("/google")
def google_login(req: GoogleLoginRequest, request: Request):
    google_client_id = os.getenv("GOOGLE_CLIENT_ID")
    if not google_client_id:
        raise HTTPException(status_code=500, detail="Google login is not configured")

    if not req.credential:
        raise HTTPException(status_code=400, detail="Missing Google credential")

    try:
        response = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": req.credential},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException:
        raise HTTPException(status_code=401, detail="Unable to verify Google account")

    if payload.get("aud") != google_client_id:
        raise HTTPException(status_code=401, detail="Google client mismatch")
    if payload.get("email_verified") not in ("true", True):
        raise HTTPException(status_code=401, detail="Google email is not verified")

    email = payload.get("email")
    google_sub = payload.get("sub")
    if not email or not google_sub:
        raise HTTPException(status_code=401, detail="Incomplete Google account data")

    user = get_or_create_google_user(email, google_sub)
    token = create_token(user[0], user[1], user[2])
    record_action(user[0], ACTION_GOOGLE_LOGIN, "users", request=request)
    return {"token": token, "email": user[1], "role": user[2]}


@router.post("/logout")
def logout(request: Request, current: CurrentUser = Depends(get_current_user)):
    """Record a logout event in the audit trail.

    Token invalidation is handled client-side (the JWT is stateless), but the
    logout action is captured for HIPAA-grade traceability.
    """
    record_action(current.id, ACTION_LOGOUT, "users", request=request)
    return {"status": "ok"}
