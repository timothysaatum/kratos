"""
Flexible JWT Authentication Router with Auto Device Registration
Supports two token generation flows:
1. Admin-generated tokens (sent via SMS/email) - device registered on first use
2. Self-service tokens - device registered during generation
"""
import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.middleware.auth_middleware import (
    get_admin_from_env,
    get_current_admin,
    rate_limit_auth,
)
from app.models.electorates import Electorate, VotingSession
from app.schemas.electorates import (
    AdminLoginRequest,
    AdminLoginResponse,
    AdminVerifyResponse,
    PasswordHashResponse,
    TokenVerificationRequest,
    TokenVerificationResponse,
)
from app.utils.device_fingerprinting import DeviceFingerprinter, SecurityValidator
from app.crud.crud_device_registration import (
    get_device_registration_by_fingerprint,
    create_device_registration_simple,
    ban_device,
    update_device_attempt,
)
from app.crud.crud_voting_tokens import get_voting_token_by_hash, update_token_usage
import hashlib
from app.utils.security_audit import SecurityAuditLogger
from app.utils.validators import validate_geolocation, validate_request_headers
from app.utils.security import SessionManager, TokenManager, verify_password, set_token_cookie
from datetime import timedelta
from app.middleware.auth_middleware import get_current_voter

router = APIRouter(prefix="/auth", tags=["Authentication"])
security = HTTPBearer()


@router.post("/verify-id", response_model=TokenVerificationResponse)
@rate_limit_auth
async def verify_voting_id(
    request: Request,
    response: Response,
    verification_data: TokenVerificationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify voting ID and issue JWT access token (with flexible device registration)

    This endpoint supports two scenarios:
    1. First-time use of admin-generated token → Auto-registers device
    2. Returning voter with registered device → Validates device fingerprint

    Returns a JWT token that expires in 10 minutes for secure voting session.
    Sets a refresh token in HTTP-only cookie that expires in 24 hours.
    """
    try:
        # Check if device fingerprint enforcement is enabled
        enforce_device_check = (
            os.getenv("ENFORCE_DEVICE_FINGERPRINT", "true").lower() == "true"
        )

        # 1. Validate request headers and security
        headers_valid, headers_reason = validate_request_headers(request)
        if not headers_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security validation failed: {headers_reason}",
            )

        # 2. Extract current device information
        current_device_info = DeviceFingerprinter.extract_device_info(request)
        current_fingerprint = current_device_info.get("fingerprint")

        # 3. Validate token format - Use permissive validation
        token_input = verification_data.token.strip()

        if not token_input:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Token cannot be empty"
            )

        # Remove formatting characters and normalize
        clean_token = token_input.replace("-", "").replace(" ", "").upper()

        # Basic format validation (accept all alphanumeric)
        if len(clean_token) != 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid token format. Token should be 8 characters (e.g., XX-XX-XX-XX). "
                f"Received {len(clean_token)} characters.",
            )

        if not clean_token.isalnum():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token should only contain letters and numbers",
            )

        # 4. Normalize token and fetch voting token record
        token_hash = hashlib.sha256(clean_token.encode()).hexdigest()
        voting_token = await get_voting_token_by_hash(db, token_hash)

        if not voting_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or non-existent token",
            )

        # 5. Check if token has been used before
        is_first_use = (
            voting_token.device_fingerprint is None
            or voting_token.device_fingerprint == ""
        )

        if is_first_use:
            # SCENARIO A: First-time use (admin-generated token sent via SMS/email)
            # Register device and bind it to this token

            SecurityAuditLogger.log_security_event(
                event_type="first_token_use",
                details={
                    "token_id": str(voting_token.id),
                    "electorate_id": str(voting_token.electorate_id),
                    "device_fingerprint": current_fingerprint[:16] + "...",
                },
            )

            # Create device registration
            registered_device = await create_device_registration_simple(
                db=db,
                device_fingerprint=current_fingerprint,
                device_info=current_device_info,
                electorate_id=voting_token.electorate_id,
            )

            # Bind device to token
            voting_token.device_fingerprint = current_fingerprint

            # Store location if provided
            if verification_data.current_location:
                voting_token.location_data = (
                    verification_data.current_location.model_dump()
                )

            await db.commit()

            stored_fingerprint = current_fingerprint

        else:
            # SCENARIO B: Returning voter - validate device fingerprint
            stored_fingerprint = voting_token.device_fingerprint

            # Get device registration
            registered_device = await get_device_registration_by_fingerprint(
                db, stored_fingerprint
            )

            if not registered_device:
                # Edge case: Token has fingerprint but no registration record
                SecurityAuditLogger.log_security_event(
                    event_type="missing_device_registration",
                    details={
                        "token_id": str(voting_token.id),
                        "stored_fingerprint": stored_fingerprint[:16] + "...",
                    },
                )

                # Re-create registration
                registered_device = await create_device_registration_simple(
                    db=db,
                    device_fingerprint=stored_fingerprint,
                    device_info=current_device_info,
                    electorate_id=voting_token.electorate_id,
                )

            # Check if device is banned
            if registered_device.is_banned:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Device is banned. Reason: {registered_device.ban_reason}",
                )

            # 6. Compare stored fingerprint with current fingerprint
            if stored_fingerprint != current_fingerprint:
                # Log the mismatch
                SecurityAuditLogger.log_security_event(
                    event_type="device_fingerprint_mismatch",
                    details={
                        "token_id": str(voting_token.id),
                        "electorate_id": str(voting_token.electorate_id),
                        "stored_fingerprint": stored_fingerprint[:16] + "...",
                        "current_fingerprint": current_fingerprint[:16] + "...",
                        "enforcement_enabled": enforce_device_check,
                    },
                )

                if enforce_device_check:
                    # PRODUCTION MODE: Strict device checking
                    await update_device_attempt(db, stored_fingerprint)

                    # Refresh device to get updated ban_count
                    await db.refresh(registered_device)

                    if registered_device.ban_count >= 3:
                        await ban_device(
                            db,
                            stored_fingerprint,
                            "Device banned after 3 failed verification attempts.",
                        )
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Device banned after 3 failed verification attempts.",
                        )
                    else:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Device fingerprint mismatch. This token is registered to another device. "
                            f"Warning: {registered_device.ban_count}/3 failed attempts.",
                        )
                else:
                    # Update to current device fingerprint
                    voting_token.device_fingerprint = current_fingerprint
                    registered_device.device_fingerprint = current_fingerprint
                    registered_device.device_info = current_device_info
                    await db.commit()

            # 7. Validate geolocation if provided (for returning voters)
            if verification_data.current_location and voting_token.location_data:
                current_location = verification_data.current_location.model_dump()
                stored_location = voting_token.location_data

                geo_valid, geo_reason = validate_geolocation(
                    current_location,
                    stored_location,
                    max_distance_km=50.0,
                )

                if not geo_valid:
                    if enforce_device_check:
                        # Production: block on location mismatch
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Location validation failed: {geo_reason}",
                        )
                    else:
                        # Testing: just log warning
                        print(f"TESTING MODE: Location mismatch allowed: {geo_reason}")

        # 8. Validate token (expiry/revoked) - applies to both scenarios
        # Make sure expires_at is timezone-aware
        from datetime import timezone

        expires_at = voting_token.expires_at
        if expires_at and expires_at.tzinfo is None:
            # If naive datetime, assume UTC
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        token_data = {
            "expires_at": expires_at,
            "revoked": voting_token.revoked,
            "device_fingerprint": voting_token.device_fingerprint,
            "location_data": voting_token.location_data,
        }

        is_valid, reason, flags = SecurityValidator.validate_token_usage(
            token_data,
            current_fingerprint,
            (
                verification_data.current_location.model_dump()
                if verification_data.current_location
                else None
            ),
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=reason,
            )

        # 9. Update token usage and create session
        await update_token_usage(db, voting_token.id)
        electorate = voting_token.electorate

        # Create voting session in database for tracking
        voting_session = await SessionManager.create_session(
            db=db, user_id=electorate.id, request=request, login_method="voting_token"
        )

        # 10. Generate JWT tokens
        # Access token - short-lived (10 minutes)
        access_token = TokenManager.create_access_token(
            data={
                "sub": str(electorate.id),
                "session_id": str(voting_session.id),
                "device_fingerprint": current_fingerprint,
                "type": "voting_session",
                "first_use": is_first_use,
            },
            expires_delta=timedelta(minutes=100),
        )

        # Refresh token - long-lived (24 hours)
        refresh_token = TokenManager.create_access_token(
            data={
                "sub": str(electorate.id),
                "session_id": str(voting_session.id),
                "device_fingerprint": current_fingerprint,
                "type": "refresh_token",  # This will now be preserved!
            },
            expires_delta=timedelta(hours=24),
        )

        set_token_cookie(
            response=response, 
            voter_token=refresh_token, 
            request=request
            )
        # Log session creation
        SecurityAuditLogger.log_session_creation(
            electorate_id=str(electorate.id),
            ip_address=current_device_info.get("client_ip"),
            device_fingerprint=current_fingerprint,
            session_duration=10,
        )

        return TokenVerificationResponse(
            valid=True,
            access_token=access_token,
            token_type="bearer",
            expires_in=600,  # 10 minutes in seconds
            electorate=electorate,
            message="Authentication successful"
            + (" - Device registered" if is_first_use else "")
            + (
                " [TESTING MODE - Device check disabled]"
                if not enforce_device_check
                else ""
            ),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token verification failed: {str(e)}",
        )


@router.post("/logout")
@rate_limit_auth
async def logout(
    request: Request,
    response: Response,
    current_voter: Electorate = Depends(get_current_voter),
    db: AsyncSession = Depends(get_db),
):
    """
    Logout user and clear refresh token cookie
    """
    try:
        # Extract session from access token
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = TokenManager.decode_token(token)
            session_id = payload.get("session_id")

            if session_id:
                # Terminate session
                result = await db.execute(
                    select(VotingSession).where(VotingSession.id == session_id)
                )
                session = result.scalar_one_or_none()

                if session:
                    session.terminate("User logout")
                    await db.commit()

        # Clear refresh token cookie
        response.delete_cookie(key="refresh_token", path="/")

        return {"message": "Logged out successfully"}

    except Exception as e:
        # Even if there's an error, still clear the cookie
        response.delete_cookie(key="refresh_token", path="/")
        return {"message": "Logged out successfully"}


@router.post("/refresh", response_model=TokenVerificationResponse)
@rate_limit_auth
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Refresh JWT token for extended voting session.
    Reads refresh token from HTTP-only cookie and issues new access and refresh tokens.
    """
    try:
        # Extract refresh token from cookie
        refresh_token_value = request.cookies.get("refresh_token")
        print(refresh_token_value)
        if not refresh_token_value:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No refresh token found. Please login again.",
            )

        # Decode refresh token with better error handling
        try:
            payload = TokenManager.decode_token(refresh_token_value)
        except Exception as decode_error:
            # Clear invalid refresh token
            response.delete_cookie(
                key="refresh_token",
                path="/",
                domain=None,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid or expired token: {str(decode_error)}",
            )

        session_id = payload.get("session_id")
        electorate_id = payload.get("sub")
        token_type = payload.get("type")

        # Validate token type
        if token_type != "refresh_token":
            response.delete_cookie(key="refresh_token", path="/", domain=None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type",
            )

        if not session_id or not electorate_id:
            response.delete_cookie(key="refresh_token", path="/", domain=None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )

        # Convert to UUID
        try:
            session_id = uuid.UUID(session_id)
            electorate_id = uuid.UUID(electorate_id)
        except (ValueError, AttributeError) as e:
            response.delete_cookie(key="refresh_token", path="/", domain=None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid ID format in token",
            )

        # Verify session is still valid
        from sqlalchemy.future import select
        from sqlalchemy.orm import selectinload

        result = await db.execute(
            select(VotingSession)
            .options(selectinload(VotingSession.electorate))
            .where(VotingSession.id == session_id)
        )
        session = result.scalar_one_or_none()

        if not session or not session.is_valid:
            # Clear invalid refresh token
            response.delete_cookie(key="refresh_token", path="/", domain=None)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid. Please login again.",
            )

        # Update session activity
        session.update_activity(None)  # No IP/fingerprint check
        await db.commit()

        # Issue new access token with fresh 10-minute expiration
        new_access_token = TokenManager.create_access_token(
            data={
                "sub": str(electorate_id),
                "session_id": str(session_id),
                "type": "voting_session",
            },
            expires_delta=timedelta(minutes=10),
        )

        # Issue new refresh token with fresh 24-hour expiration (token rotation)
        new_refresh_token = TokenManager.create_access_token(
            data={
                "sub": str(electorate_id),
                "session_id": str(session_id),
                "type": "refresh_token",
            },
            expires_delta=timedelta(hours=24),
        )

        # Set refresh token cookie using the helper function
        set_token_cookie(
            response=response,
            voter_token=new_refresh_token,
            request=request
        )

        return TokenVerificationResponse(
            valid=True,
            access_token=new_access_token,
            token_type="bearer",
            expires_in=600,
            electorate=session.electorate,
            message="Token refreshed successfully",
        )

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()  # Debug logging
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}",
        )


@router.get("/verify")
async def verify_current_token(
    credentials: Electorate = Depends(get_current_voter),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify current JWT token validity

    This endpoint checks if the provided JWT token is valid and active.
    """
    try:
        payload = TokenManager.decode_token(credentials.credentials)
        session_id = payload.get("session_id")

        from sqlalchemy.future import select

        result = await db.execute(
            select(VotingSession).where(VotingSession.id == session_id)
        )
        session = result.scalar_one_or_none()

        if not session or not session.is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
            )

        from datetime import datetime, timezone

        time_remaining = int(
            (session.expires_at - datetime.now(timezone.utc)).total_seconds()
        )

        return {
            "valid": True,
            "electorate_id": payload.get("sub"),
            "session_id": session_id,
            "expires_in": max(0, time_remaining),
            "device_fingerprint": payload.get("device_fingerprint", "")[:8] + "...",
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed",
        )


@router.post("/login", response_model=AdminLoginResponse)
@rate_limit_auth
async def admin_login(
    request: Request,
    login_data: AdminLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Admin login endpoint - validates credentials from environment variables.

    Required environment variables:
    - ADMIN_USERNAME: Admin username
    - ADMIN_PASSWORD_HASH: Argon2 hashed password
    - ADMIN_PERMISSIONS: (Optional) Comma-separated permissions

    Returns JWT token for admin operations (valid for 8 hours).
    """
    try:
        # 1. Get admin config from environment variables
        admin_config = get_admin_from_env()

        if not admin_config:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Admin credentials not configured in environment variables. "
                "Please set ADMIN_USERNAME and ADMIN_PASSWORD_HASH in .env file.",
            )

        # 2. Verify username
        if login_data.username != admin_config["username"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin credentials",
            )

        # 3. Verify password against hash from environment
        try:
            if not verify_password(admin_config["password_hash"], login_data.password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid admin credentials",
                )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin credentials",
            )

        # 4. Create admin JWT token with 8 hour expiration
        access_token = TokenManager.create_access_token(
            data={
                "sub": login_data.username,
                "role": "admin",
                "type": "admin_access",
                "permissions": admin_config["permissions"],
            },
            expires_delta=timedelta(hours=8),
        )

        # 5. Log admin login
        device_info = DeviceFingerprinter.extract_device_info(request)

        from app.middleware.auth_middleware import SecurityAuditLogger

        SecurityAuditLogger.log_admin_action(
            admin_username=login_data.username,
            action="login",
            resource="admin_auth",
            ip_address=device_info.get("client_ip"),
            details={"success": True},
        )

        return AdminLoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=28800,  # 8 hours in seconds
            username=login_data.username,
            role="admin",
            permissions=admin_config["permissions"],
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Admin login failed: {str(e)}",
        )


@router.post("/admin/logout")
async def admin_logout(
    request: Request,
    admin: dict = Depends(get_current_admin),
):
    """
    Admin logout endpoint.

    Note: With JWT, logout is handled client-side by removing the token.
    This endpoint is mainly for logging purposes.
    """
    try:
        from app.middleware.auth_middleware import SecurityAuditLogger

        device_info = DeviceFingerprinter.extract_device_info(request)
        SecurityAuditLogger.log_admin_action(
            admin_username=admin["username"],
            action="logout",
            resource="admin_auth",
            ip_address=device_info.get("client_ip"),
            details={"success": True},
        )

        return {"message": "Successfully logged out", "username": admin["username"]}
    except:
        return {"message": "Logged out"}


@router.get("/admin/verify", response_model=AdminVerifyResponse)
async def verify_admin_token(
    admin: dict = Depends(get_current_admin),
):
    """
    Verify admin token validity.

    Returns admin information if token is valid.
    """
    return AdminVerifyResponse(
        valid=True,
        username=admin["username"],
        role=admin["role"],
        permissions=admin["permissions"],
    )


@router.post("/generate-password-hash", response_model=PasswordHashResponse)
async def generate_password_hash(
    password: str,
):
    """
    Generate Argon2 password hash for use in environment variables.

    SECURITY WARNING: This endpoint should be DISABLED in production!
    Only use this for initial setup or in development environments.
    """
    environment = os.getenv("ENVIRONMENT", "development").lower()
    if environment in ["production", "prod"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password hash generation is disabled in production for security reasons",
        )

    try:
        if not password or len(password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 6 characters long",
            )

        from argon2 import PasswordHasher

        ph = PasswordHasher(
            time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16
        )
        password_hash = ph.hash(password)

        return PasswordHashResponse(
            password_hash=password_hash,
            message="Copy this hash to ADMIN_PASSWORD_HASH in your .env file. "
            "Keep this hash secret and never commit it to version control!",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate password hash: {str(e)}",
        )
