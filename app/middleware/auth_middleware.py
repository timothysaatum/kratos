"""
Authentication Middleware for Secure Token Verification

This middleware provides comprehensive token verification with device fingerprinting,
location verification, and security checks for the voting system.

FIXED: Uses HTTPBearer only (no OAuth2PasswordBearer) for clean Swagger UI
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
from typing import Dict, Any, Optional
import hashlib
import logging
from functools import wraps
from collections import defaultdict
import time

# Set up logging
logger = logging.getLogger(__name__)

security_scheme = HTTPBearer()
admin_security_scheme = HTTPBearer()


class SecureAuthMiddleware:
    """Secure authentication middleware with comprehensive verification"""

    @staticmethod
    async def verify_voting_token(
        request: Request, token: str, db: AsyncSession, require_location: bool = False
    ) -> Dict[str, Any]:
        """
        Comprehensive token verification with device and location checks

        Args:
            request: FastAPI request object
            token: JWT token string
            db: Database session
            require_location: Whether location verification is required

        Returns:
            Dictionary containing verification results and electorate data

        Raises:
            HTTPException: If verification fails
        """
        try:
            # 1. Extract current device information
            current_device_info = DeviceFingerprinter.extract_device_info(request)
            current_fingerprint = current_device_info.get("fingerprint")

            # 2. Decode JWT token
            try:
                payload = TokenManager.decode_token(token)
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token: {str(e)}",
                )

            # 3. Get token from database
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            voting_token = await get_voting_token_by_hash(db, token_hash)

            if not voting_token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token not found in database",
                )

            # 4. Validate token data
            token_data = {
                "expires_at": voting_token.expires_at,
                "revoked": voting_token.revoked,
                "device_fingerprint": voting_token.device_fingerprint,
                "location_data": voting_token.location_data,
            }

            # Extract location from request if available
            current_location = None
            if require_location:
                latitude = request.headers.get("X-Location-Latitude")
                longitude = request.headers.get("X-Location-Longitude")

                if latitude and longitude:
                    current_location = {
                        "latitude": float(latitude),
                        "longitude": float(longitude),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

            # 5. Perform comprehensive validation
            is_valid, reason, flags = SecurityValidator.validate_token_usage(
                token_data, current_fingerprint, current_location
            )

            if not is_valid:
                error_detail = reason
                if flags.get("device_mismatch"):
                    error_detail += " (Device fingerprint mismatch)"
                if flags.get("location_mismatch"):
                    error_detail += " (Location mismatch)"

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail=error_detail
                )

            # 6. Update token usage
            await update_token_usage(db, voting_token.id)

            # 7. Get electorate information
            electorate = voting_token.electorate
            if not electorate:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Associated electorate not found",
                )

            # 8. Additional security checks
            if electorate.is_banned:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Electorate is banned"
                )

            if electorate.is_deleted:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Electorate not found"
                )

            # 9. Return verification results
            return {
                "electorate": electorate,
                "voting_token": voting_token,
                "device_info": current_device_info,
                "verification_flags": flags,
                "token_payload": payload,
            }

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Token verification failed",
            )


# ============================================================================
# PRIMARY VOTER AUTHENTICATION DEPENDENCY
# ============================================================================


async def get_current_voter(
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    request: Request = None,
) -> Electorate:
    """
    Get current authenticated voter with enhanced session validation.

    Usage in routes:
        @router.post("/vote")
        async def cast_vote(
            voter: Electorate = Depends(get_current_voter)
        ):
            # Access voter properties directly:
            # voter.id, voter.student_id, voter.voting_tokens, etc.
            pass
    """
    token = credentials.credentials  # Extract token from HTTPAuthorizationCredentials

    try:
        # 1. Decode JWT token
        payload = TokenManager.decode_token(token)
        electorate_id = payload.get("sub")
        session_id = payload.get("session_id")
        stored_fingerprint = payload.get("device_fingerprint")

        if electorate_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token does not contain user ID",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if payload.get("type") != "access" and payload.get("type") != "voting_session":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 2. Get electorate with relationships
        result = await db.execute(
            select(Electorate)
            .options(
                selectinload(Electorate.voting_tokens),
                # selectinload(Electorate.device_registrations),
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

        # 3. Check voter status
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

        # 4. Validate session if session ID is in token and request is available
        if session_id and request:
            session = await _validate_voter_session(
                db, UUID(session_id), request, voter.id, stored_fingerprint
            )
            if not session:
                logger.warning(
                    f"Invalid session detected - Voter: {voter.id}, Session: {session_id}"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired session",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return voter

    except (JWTError, ValueError) as e:
        logger.warning(f"Invalid authentication credentials: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================


async def get_current_electorate_from_session(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> Electorate:
    """
    Backward compatibility - use get_current_voter instead
    """
    return await get_current_voter(db, credentials, request)


# ============================================================================
# ADMIN AUTHENTICATION
# ============================================================================


def get_admin_from_env() -> Optional[dict]:
    """
    Get admin credentials from environment variables.

    Environment variables:
        ADMIN_USERNAME: Admin username
        ADMIN_PASSWORD_HASH: Argon2 hashed password
        ADMIN_PERMISSIONS: Comma-separated list of permissions (optional)

    Returns admin config or None if not configured.
    """
    username = os.getenv("ADMIN_USERNAME")
    password_hash = os.getenv("ADMIN_PASSWORD_HASH")

    if not username or not password_hash:
        return None

    # Get permissions from env or use defaults
    permissions_str = os.getenv("ADMIN_PERMISSIONS", "")
    if permissions_str:
        permissions = [p.strip() for p in permissions_str.split(",")]
    else:
        # Default admin permissions
        permissions = [
            "manage_portfolios",
            "manage_candidates",
            "manage_elections",
            "view_results",
            "manage_electorates",
        ]

    return {
        "username": username,
        "password_hash": password_hash,
        "permissions": permissions,
        "role": "admin",
    }


async def get_current_admin(
    db: AsyncSession = Depends(get_db),
    credentials: HTTPAuthorizationCredentials = Depends(admin_security_scheme),
    request: Request = None,
) -> dict:
    """
    Get current authenticated admin user from JWT token.
    Admin credentials are validated against environment variables.

    Usage in admin routes:
        @router.post("/portfolios")
        async def create_portfolio(
            admin: dict = Depends(get_current_admin),
            portfolio_data: PortfolioCreate
        ):
            # Admin is authenticated and authorized
            # Access: admin["username"], admin["permissions"]
            pass
    """
    token = credentials.credentials  # Extract token from HTTPAuthorizationCredentials

    try:
        # 1. Decode JWT token
        payload = TokenManager.decode_token(token)
        username = payload.get("sub")
        role = payload.get("role")

        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token does not contain username",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify this is an admin token
        if role != "admin" and role != "super_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized as admin",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 2. Verify admin exists in environment variables
        admin_config = get_admin_from_env()
        if not admin_config:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Admin not configured in environment variables",
            )

        # Verify username matches
        if username != admin_config["username"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin username",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 3. Log admin activity
        if request:
            device_info = DeviceFingerprinter.extract_device_info(request)
            logger.info(
                f"Admin access - Username: {username}, "
                f"IP: {device_info.get('client_ip')}, "
                f"Endpoint: {request.url.path}"
            )

        # 4. Return admin info
        return {
            "username": username,
            "role": role,
            "permissions": payload.get("permissions", admin_config["permissions"]),
        }

    except (JWTError, ValueError) as e:
        logger.warning(f"Invalid admin authentication credentials: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_admin_permission(required_permission: str):
    """
    Dependency factory for permission-based access control.

    Usage:
        @router.delete("/portfolios/{id}")
        async def delete_portfolio(
            portfolio_id: str,
            admin: dict = Depends(require_admin_permission("manage_portfolios"))
        ):
            # Admin has the required permission
            pass
    """

    async def check_permission(admin: dict = Depends(get_current_admin)) -> dict:
        if required_permission not in admin.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {required_permission}",
            )
        return admin

    return check_permission


async def get_super_admin(admin: dict = Depends(get_current_admin)) -> dict:
    """
    Require super admin access (highest level).

    Usage:
        @router.post("/admin/create")
        async def create_admin(
            admin: dict = Depends(get_super_admin)
        ):
            # Only super admins can create other admins
            pass
    """
    if admin.get("role") != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Super admin access required"
        )
    return admin


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


async def _validate_voter_session(
    db: AsyncSession,
    session_id: UUID,
    request: Request,
    electorate_id: UUID,
    stored_fingerprint: Optional[str] = None,
) -> Optional[VotingSession]:
    """
    Validate voting session with comprehensive security checks.
    Returns session if valid, None otherwise.
    """
    # Get session from database
    result = await db.execute(
        select(VotingSession).where(VotingSession.id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        return None

    # Check if session is valid and not expired
    expires_at = session.expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc) 
          
    if not session.is_valid or expires_at < datetime.now(timezone.utc):
        if session.is_valid:
            session.terminate("Session expired")
            await db.commit()
        return None

    # Verify session belongs to correct voter
    if session.electorate_id != electorate_id:
        session.terminate("Session electorate mismatch")
        await db.commit()
        return None

    # Verify device fingerprint if provided
    if stored_fingerprint and request:
        current_device_info = DeviceFingerprinter.extract_device_info(request)
        current_fingerprint = current_device_info.get("fingerprint")

        if stored_fingerprint != current_fingerprint:
            session.terminate("Device fingerprint mismatch")
            await db.commit()
            logger.warning(
                f"Device fingerprint mismatch - Session: {session_id}, "
                f"Voter: {electorate_id}"
            )
            return None

    # Check for suspicious activity
    if session.suspicious_activity:
        session.terminate("Suspicious activity detected")
        await db.commit()
        logger.error(
            f"Suspicious activity - Session: {session_id}, Voter: {electorate_id}"
        )
        return None

    # Extract current IP
    current_ip = (
        getattr(request.client, "host", "unknown")
        if request and request.client
        else "unknown"
    )

    # Check for concurrent sessions
    concurrent_sessions_result = await db.execute(
        select(VotingSession).where(
            VotingSession.electorate_id == electorate_id,
            VotingSession.is_valid == True,
            VotingSession.id != session_id,
        )
    )
    concurrent_sessions = concurrent_sessions_result.scalars().all()

    if concurrent_sessions:
        # Terminate other sessions
        for other_session in concurrent_sessions:
            other_session.terminate("Concurrent session detected")
        logger.warning(
            f"Concurrent sessions detected and terminated - Voter: {electorate_id}, "
            f"Count: {len(concurrent_sessions)}"
        )

    # Update session activity
    session.update_activity(current_ip)

    # Check for excessive activity (potential bot)
    if session.activity_count > 100:
        session.terminate("Excessive activity detected")
        await db.commit()
        logger.error(
            f"Excessive activity - Session: {session_id}, "
            f"Count: {session.activity_count}"
        )
        return None

    await db.commit()
    return session


# ============================================================================
# RATE LIMITING
# ============================================================================


class RateLimiter:
    """Simple rate limiter for authentication endpoints"""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = defaultdict(list)

    def is_rate_limited(self, identifier: str) -> bool:
        """Check if identifier is rate limited"""
        now = time.time()
        # Clean old attempts
        self.attempts[identifier] = [
            attempt_time
            for attempt_time in self.attempts[identifier]
            if now - attempt_time < self.window_seconds
        ]

        # Check if over limit
        if len(self.attempts[identifier]) >= self.max_attempts:
            return True

        # Record this attempt
        self.attempts[identifier].append(now)
        return False


# Global rate limiter instances
auth_rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
voting_rate_limiter = RateLimiter(max_attempts=3, window_seconds=900)
session_rate_limiter = RateLimiter(max_attempts=10, window_seconds=60)


def rate_limit_auth(func):
    """Decorator to add rate limiting to authentication functions"""

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


# def rate_limit_voting(func):
#     """Decorator to add rate limiting to voting functions"""

#     @wraps(func)
#     async def wrapper(request: Request, *args, **kwargs):
#         device_info = DeviceFingerprinter.extract_device_info(request)
#         client_ip = device_info.get("client_ip", "unknown")

#         if voting_rate_limiter.is_rate_limited(client_ip):
#             raise HTTPException(
#                 status_code=status.HTTP_429_TOO_MANY_REQUESTS,
#                 detail="Too many voting attempts. Please wait before trying again.",
#             )

#         return await func(request, *args, **kwargs)


#     return wrapper
def rate_limit_voting(func):
    """Decorator to add rate limiting to voting functions"""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Try to get the request object from either kwargs or args
        request = kwargs.get("request") or next(
            (a for a in args if isinstance(a, Request)), None
        )

        if not request:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Request object not found in rate_limit_voting decorator.",
            )

        # Extract client IP or device info
        device_info = DeviceFingerprinter.extract_device_info(request)
        client_ip = device_info.get("client_ip", "unknown")

        # Apply rate limiting
        if voting_rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many voting attempts. Please wait before trying again.",
            )

        # Proceed with the endpoint
        return await func(*args, **kwargs)

    return wrapper


def rate_limit_session(func):
    """Decorator to add rate limiting to session operations"""

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        device_info = DeviceFingerprinter.extract_device_info(request)
        client_ip = device_info.get("client_ip", "unknown")

        if session_rate_limiter.is_rate_limited(client_ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many session requests. Please slow down.",
            )

        return await func(request, *args, **kwargs)

    return wrapper


# ============================================================================
# SECURITY AUDIT LOGGING
# ============================================================================


class SecurityAuditLogger:
    """Security audit logging for authentication events"""

    @staticmethod
    def log_successful_auth(
        electorate_id: str, device_fingerprint: str, ip_address: str
    ):
        """Log successful authentication"""
        logger.info(
            f"Successful authentication - Electorate: {electorate_id}, "
            f"Device: {device_fingerprint[:8]}..., IP: {ip_address}"
        )

    @staticmethod
    def log_failed_auth(reason: str, device_fingerprint: str, ip_address: str):
        """Log failed authentication attempt"""
        logger.warning(
            f"Failed authentication - Reason: {reason}, "
            f"Device: {device_fingerprint[:8]}..., IP: {ip_address}"
        )

    @staticmethod
    def log_security_violation(
        violation_type: str, ip_address: str, device_fingerprint: str, details: dict
    ):
        """Log security violations"""
        logger.error(
            f"Security violation - Type: {violation_type}, "
            f"IP: {ip_address}, Device: {device_fingerprint[:8]}..., "
            f"Details: {details}"
        )

    @staticmethod
    def log_admin_action(
        admin_username: str,
        action: str,
        resource: str,
        ip_address: str,
        details: dict = None,
    ):
        """Log admin actions for audit trail"""
        logger.info(
            f"Admin action - Username: {admin_username}, "
            f"Action: {action}, Resource: {resource}, "
            f"IP: {ip_address}, Details: {details or {}}"
        )
