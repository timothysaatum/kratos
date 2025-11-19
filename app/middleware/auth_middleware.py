"""
Authentication Middleware with Multi-Role Support
Supports: admin, ec_official, polling_agent
"""

import os
from uuid import UUID
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.models.electorates import Electorate, VotingSession
from app.utils.device_fingerprinting import DeviceFingerprinter, SecurityValidator
from app.utils.security import TokenManager
from app.crud.crud_voting_tokens import get_voting_token_by_hash, update_token_usage
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import hashlib
import logging
from functools import wraps
from collections import defaultdict
import time

logger = logging.getLogger(__name__)

security_scheme = HTTPBearer()
admin_security_scheme = HTTPBearer()


# ============================================================================
# MULTI-USER ENVIRONMENT CONFIGURATION
# ============================================================================


def get_all_users_from_env() -> Dict[str, dict]:
    """
    Parse all users from environment variables with role-based prefixes.

    FIXED: Handles commas in Argon2 hashes correctly
    """
    users = {}

    # Method 2: Role-specific variables (MORE RELIABLE)
    # Admin users
    admin_users_str = os.getenv("ADMIN_USERS", "")
    if admin_users_str:
        # Split by comma, but be careful of Argon2 hashes containing commas
        # Expected format: username:$argon2id$v=19$m=65536,t=3,p=1$salt$hash
        # Strategy: Split on comma only if followed by a username pattern (letters followed by colon)

        import re

        # Split entries by looking for patterns like "username:" at the start
        entries = re.split(r",(?=[a-zA-Z0-9_]+:)", admin_users_str)

        for user_entry in entries:
            user_entry = user_entry.strip()
            # Split only on the FIRST colon to separate username from hash
            if ":" in user_entry:
                username, password_hash = user_entry.split(":", 1)  # maxsplit=1 is KEY!
                users[username] = {
                    "username": username,
                    "password_hash": password_hash,
                    "role": "admin",
                    "permissions": _get_permissions_for_role("admin"),
                }

    # EC Official users
    ec_users_str = os.getenv("EC_OFFICIAL_USERS", "")
    if ec_users_str:
        import re

        entries = re.split(r",(?=[a-zA-Z0-9_]+:)", ec_users_str)

        for user_entry in entries:
            user_entry = user_entry.strip()
            if ":" in user_entry:
                username, password_hash = user_entry.split(":", 1)
                users[username] = {
                    "username": username,
                    "password_hash": password_hash,
                    "role": "ec_official",
                    "permissions": _get_permissions_for_role("ec_official"),
                }

    # Polling Agent users
    agent_users_str = os.getenv("POLLING_AGENT_USERS", "")
    if agent_users_str:
        import re

        entries = re.split(r",(?=[a-zA-Z0-9_]+:)", agent_users_str)

        for user_entry in entries:
            user_entry = user_entry.strip()
            if ":" in user_entry:
                username, password_hash = user_entry.split(":", 1)
                users[username] = {
                    "username": username,
                    "password_hash": password_hash,
                    "role": "polling_agent",
                    "permissions": _get_permissions_for_role("polling_agent"),
                }

    # Fallback: Legacy single admin support
    if not users:
        legacy_admin = get_admin_from_env()
        if legacy_admin:
            users[legacy_admin["username"]] = legacy_admin

    return users


def _get_permissions_for_role(role: str) -> List[str]:
    """Get default permissions for each role"""
    permissions_map = {
        "admin": [
            "manage_portfolios",
            "manage_candidates",
            "manage_elections",
            "manage_electorates",
            "generate_tokens",
            "view_results",
            "manage_users",
        ],
        "ec_official": ["generate_tokens", "view_electorates", "verify_voters"],
        "polling_agent": ["view_results", "view_statistics"],
    }
    return permissions_map.get(role, [])


def get_user_by_username(username: str) -> Optional[dict]:
    """Get user configuration by username"""
    all_users = get_all_users_from_env()
    return all_users.get(username)


def get_admin_from_env() -> Optional[dict]:
    """
    Legacy function - Get admin credentials from environment variables.
    Kept for backward compatibility.
    """
    username = os.getenv("ADMIN_USERNAME")
    password_hash = os.getenv("ADMIN_PASSWORD_HASH")

    if not username or not password_hash:
        return None

    permissions_str = os.getenv("ADMIN_PERMISSIONS", "")
    if permissions_str:
        permissions = [p.strip() for p in permissions_str.split(",")]
    else:
        permissions = _get_permissions_for_role("admin")

    return {
        "username": username,
        "password_hash": password_hash,
        "permissions": permissions,
        "role": "admin",
    }


# ============================================================================
# ADMIN/STAFF AUTHENTICATION (Multi-Role)
# ============================================================================


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(admin_security_scheme),
    request: Request = None,
) -> dict:
    """
    Get current authenticated user (admin, ec_official, or polling_agent).

    Returns user dict with: username, role, permissions, is_admin
    """
    token = credentials.credentials

    print(f"Received token (first 50 chars): {token[:50]}")
    try:
        # Decode JWT token
        print("Great one, I salute you")
        payload = TokenManager.decode_token(token)
        username = payload.get("sub")
        role = payload.get("role")
        token_type = payload.get("type")  # Add this line
        print(f"Token payload: {payload}")
        # Validate token type for admin/staff authentication
        if token_type not in ["admin_access", "access", None]:  # Add this check
            print("Hello")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for admin authentication",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token does not contain username",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify valid role
        if role not in ["admin", "ec_official", "polling_agent"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid user role",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify user exists in environment
        user_config = get_user_by_username(username)
        if not user_config:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found in configuration",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify role matches
        if user_config["role"] != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role mismatch",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Log activity
        if request:
            device_info = DeviceFingerprinter.extract_device_info(request)
            logger.info(
                f"User access - Username: {username}, Role: {role}, "
                f"IP: {device_info.get('client_ip')}, "
                f"Endpoint: {request.url.path}"
            )

        # Return user info with is_admin flag for backward compatibility
        return {
            "username": username,
            "role": role,
            "permissions": payload.get("permissions", user_config["permissions"]),
            "is_admin": role == "admin",  # For backward compatibility
        }

    except (JWTError, ValueError) as e:
        logger.warning(f"Invalid authentication credentials: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_admin(user: dict = Depends(get_current_user)) -> dict:
    """
    Require admin role specifically.
    Use this for admin-only endpoints.
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        )
    return user


async def get_current_ec_official(user: dict = Depends(get_current_user)) -> dict:
    """
    Require ec_official role (or admin).
    Use this for EC official endpoints.
    """
    if user["role"] not in ["admin", "ec_official"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="EC Official access required"
        )
    return user


async def get_current_polling_agent(user: dict = Depends(get_current_user)) -> dict:
    """
    Require polling_agent role (or admin).
    Use this for polling agent endpoints.
    """
    if user["role"] not in ["admin", "polling_agent"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Polling Agent access required",
        )
    return user


def require_permission(required_permission: str):
    """
    Dependency factory for permission-based access control.
    """

    async def check_permission(user: dict = Depends(get_current_user)) -> dict:
        if required_permission not in user.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {required_permission}",
            )
        return user

    return check_permission


# ============================================================================
# VOTER AUTHENTICATION (Unchanged)
# ============================================================================


async def get_current_voter(
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    request: Request = None,
) -> Electorate:
    """
    Get current authenticated voter with enhanced session validation.
    """
    token = credentials.credentials

    try:
        # Decode JWT token
        payload = TokenManager.decode_token(token)
        electorate_id = payload.get("sub")
        session_id = payload.get("session_id")
        stored_fingerprint = payload.get("device_fingerprint")
        token_type = payload.get("type")

        if electorate_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token does not contain user ID",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check token type - CRITICAL FIX
        if token_type not in ["access", "voting_session"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for voter authentication",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get electorate with relationships
        result = await db.execute(
            select(Electorate)
            .options(
                selectinload(Electorate.voting_tokens),
                selectinload(Electorate.voting_sessions),
            )
            .where(Electorate.id == UUID(electorate_id))
        )
        voter = result.scalar_one_or_none()

        if voter is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Voter not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check voter status
        if voter.is_banned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is banned",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if voter.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Account not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate session
        if session_id and request:
            session = await _validate_voter_session(
                db, UUID(session_id), request, voter.id, stored_fingerprint
            )
            if not session:
                logger.warning(
                    f"Invalid session - Voter: {voter.id}, Session: {session_id}"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired session",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return voter

    except (JWTError, ValueError) as e:
        logger.warning(f"Invalid voter authentication: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def _validate_voter_session(
    db: AsyncSession,
    session_id: UUID,
    request: Request,
    electorate_id: UUID,
    stored_fingerprint: Optional[str] = None,
) -> Optional[VotingSession]:
    """Validate voting session with comprehensive security checks."""
    result = await db.execute(
        select(VotingSession).where(VotingSession.id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        return None

    expires_at = session.expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if not session.is_valid or expires_at < datetime.now(timezone.utc):
        if session.is_valid:
            session.terminate("Session expired")
            await db.commit()
        return None

    if session.electorate_id != electorate_id:
        session.terminate("Session electorate mismatch")
        await db.commit()
        return None

    if stored_fingerprint and request:
        current_device_info = DeviceFingerprinter.extract_device_info(request)
        current_fingerprint = current_device_info.get("fingerprint")

        if stored_fingerprint != current_fingerprint:
            session.terminate("Device fingerprint mismatch")
            await db.commit()
            return None

    if session.suspicious_activity:
        session.terminate("Suspicious activity detected")
        await db.commit()
        return None

    current_ip = (
        getattr(request.client, "host", "unknown")
        if request and request.client
        else "unknown"
    )

    session.update_activity(current_ip)
    await db.commit()
    return session


# ============================================================================
# RATE LIMITING (Unchanged)
# ============================================================================


class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(list)

    def is_rate_limited(self, identifier: str) -> bool:
        now = time.time()
        self.attempts[identifier] = [
            attempt_time
            for attempt_time in self.attempts[identifier]
            if now - attempt_time < self.window_seconds
        ]

        if len(self.attempts[identifier]) >= self.max_attempts:
            return True

        self.attempts[identifier].append(now)
        return False


auth_rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
voting_rate_limiter = RateLimiter(max_attempts=3, window_seconds=900)


def rate_limit_auth(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        device_info = DeviceFingerprinter.extract_device_info(request)
        client_ip = device_info.get("client_ip", "unknown")

        if auth_rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please try again later.",
            )

        return await func(request, *args, **kwargs)

    return wrapper


def rate_limit_voting(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get("request") or next(
            (a for a in args if isinstance(a, Request)), None
        )

        if not request:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Request object not found.",
            )

        device_info = DeviceFingerprinter.extract_device_info(request)
        client_ip = device_info.get("client_ip", "unknown")

        if voting_rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many voting attempts. Please wait.",
            )

        return await func(*args, **kwargs)

    return wrapper


# ============================================================================
# SECURITY AUDIT LOGGING
# ============================================================================


class SecurityAuditLogger:
    @staticmethod
    def log_successful_auth(
        electorate_id: str, device_fingerprint: str, ip_address: str
    ):
        logger.info(
            f"Successful authentication - Electorate: {electorate_id}, "
            f"Device: {device_fingerprint[:8]}..., IP: {ip_address}"
        )

    @staticmethod
    def log_failed_auth(reason: str, device_fingerprint: str, ip_address: str):
        logger.warning(
            f"Failed authentication - Reason: {reason}, "
            f"Device: {device_fingerprint[:8]}..., IP: {ip_address}"
        )

    @staticmethod
    def log_security_event(event_type: str, details: dict):
        logger.warning(f"Security event - Type: {event_type}, Details: {details}")

    @staticmethod
    def log_session_creation(
        electorate_id: str,
        ip_address: str,
        device_fingerprint: str,
        session_duration: int,
    ):
        logger.info(
            f"Session created - Electorate: {electorate_id}, "
            f"IP: {ip_address}, Duration: {session_duration}min"
        )

    @staticmethod
    def log_admin_action(
        admin_username: str,
        action: str,
        resource: str,
        ip_address: str,
        details: dict = None,
    ):
        logger.info(
            f"Admin action - User: {admin_username}, Role: {details.get('role', 'unknown')}, "
            f"Action: {action}, Resource: {resource}, IP: {ip_address}"
        )
