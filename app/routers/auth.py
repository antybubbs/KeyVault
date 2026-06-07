import time
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.core.csrf import csrf_context, validate_csrf_token
from app.core.security import hash_password, verify_password
from app.db.session import get_db
from app.models.models import User
from app.services.audit import write_audit

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_FAILURES: dict[str, list[float]] = {}
DUMMY_PASSWORD_HASH = hash_password("not-the-real-password")


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def login_is_limited(key: str) -> bool:
    now = time.monotonic()
    attempts = [attempt for attempt in LOGIN_FAILURES.get(key, []) if now - attempt < LOGIN_WINDOW_SECONDS]
    LOGIN_FAILURES[key] = attempts
    return len(attempts) >= MAX_LOGIN_ATTEMPTS


def record_login_failure(key: str) -> None:
    now = time.monotonic()
    attempts = [attempt for attempt in LOGIN_FAILURES.get(key, []) if now - attempt < LOGIN_WINDOW_SECONDS]
    attempts.append(now)
    LOGIN_FAILURES[key] = attempts


def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id, User.is_active == True).first()


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = current_user(request, db)
    if not user:
        raise PermissionError("Authentication required")
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    user = require_user(request, db)
    if user.role != "admin":
        raise PermissionError("Admin access required")
    return user


def require_editor(request: Request, db: Session = Depends(get_db)) -> User:
    user = require_user(request, db)
    if user.role not in ["admin", "editor"]:
        raise PermissionError("Editor access required")
    return user


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None, **csrf_context(request, include_version=False)})


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf_token(request, csrf_token)
    key = client_key(request)
    if login_is_limited(key):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Too many failed sign-in attempts. Try again later.", **csrf_context(request, include_version=False)}, status_code=429)
    user = db.query(User).filter(User.email == email.strip().lower(), User.is_active == True).first()
    password_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    if not verify_password(password, password_hash) or not user:
        record_login_failure(key)
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password", **csrf_context(request, include_version=False)}, status_code=401)
    request.session.clear()
    request.session["user_id"] = user.id
    LOGIN_FAILURES.pop(key, None)
    write_audit(db, user, "login", "user", str(user.id), request.client.host if request.client else None)
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    validate_csrf_token(request, csrf_token)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
