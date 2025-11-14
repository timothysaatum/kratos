from fastapi import Request, Response
import ipaddress
import uuid
from argon2 import PasswordHasher
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from typing import Optional
import os
import hashlib
from fastapi import Request
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.electorates import VotingSession
from sqlalchemy.future import select
from uuid import UUID
from sqlalchemy.orm import selectinload
from uuid import uuid4
import secrets

from app.schemas.electorates import VoterSession

load_dotenv()

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY")
assert SECRET_KEY, "SECRET_KEY is not set in the .env file"

# JWT and Token Configuration
ALGORITHM = os.getenv("ALGORITHM", "HS256")
# Change default to 10 minutes for voting sessions
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "10"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Account lockout configuration
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_DURATION_MINUTES", "15"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
IS_PRODUCTION = ENVIRONMENT.lower() in ["production", "prod"]

# Argon2 password hashing configuration
ph = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


class FriendlyTokenGenerator:
    """Generate user-friendly voting tokens that are easy to type and remember"""

    # Character sets for different token formats
    UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz"
    DIGITS = "0123456789"
    # Exclude confusing characters: 0, O, I, l, 1
    SAFE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

    @staticmethod
    def generate_readable_token(length: int = 8, format_type: str = "mixed") -> str:
        """
        Generate a user-friendly token

        Args:
            length: Length of the token
            format_type: "mixed", "uppercase", "lowercase", "digits", "safe"

        Returns:
            User-friendly token string
        """
        if format_type == "mixed":
            # Mix of uppercase, lowercase, and digits
            chars = (
                FriendlyTokenGenerator.UPPERCASE_LETTERS
                + FriendlyTokenGenerator.LOWERCASE_LETTERS
                + FriendlyTokenGenerator.DIGITS
            )
        elif format_type == "uppercase":
            chars = FriendlyTokenGenerator.UPPERCASE_LETTERS
        elif format_type == "lowercase":
            chars = FriendlyTokenGenerator.LOWERCASE_LETTERS
        elif format_type == "digits":
            chars = FriendlyTokenGenerator.DIGITS
        elif format_type == "safe":
            # Exclude confusing characters
            chars = FriendlyTokenGenerator.SAFE_CHARS
        else:
            chars = FriendlyTokenGenerator.SAFE_CHARS

        return "".join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def generate_word_token() -> str:
        """
        Generate a token using readable words separated by hyphens
        Example: VOTE-2024-ALPHA-BETA
        """
        # Simple word list for token generation
        words = [
            "ALPHA",
            "BETA",
            "GAMMA",
            "DELTA",
            "ECHO",
            "FOXTROT",
            "GOLF",
            "HOTEL",
            "INDIA",
            "JULIET",
            "KILO",
            "LIMA",
            "MIKE",
            "NOVEMBER",
            "OSCAR",
            "PAPA",
            "QUEBEC",
            "ROMEO",
            "SIERRA",
            "TANGO",
            "UNIFORM",
            "VICTOR",
            "WHISKEY",
            "XRAY",
            "YANKEE",
            "ZULU",
        ]

        # Generate 2-3 words
        num_words = secrets.choice([2, 3])
        selected_words = secrets.sample(words, num_words)

        # Add a number
        number = secrets.randbelow(9999) + 1000  # 1000-9999

        return f"{'-'.join(selected_words)}-{number}"

    @staticmethod
    def generate_numeric_code(length: int = 6) -> str:
        """
        Generate a numeric code (like SMS verification)
        Example: 123456
        """
        return "".join(
            secrets.choice(FriendlyTokenGenerator.DIGITS) for _ in range(length)
        )

    @staticmethod
    def generate_alphanumeric_code(length: int = 8) -> str:
        """
        Generate alphanumeric code with clear separation
        Example: AB12-CD34-EF56
        """
        chars = FriendlyTokenGenerator.UPPERCASE_LETTERS + FriendlyTokenGenerator.DIGITS
        code = "".join(secrets.choice(chars) for _ in range(length))

        # Add hyphens for readability
        if length >= 6:
            return "-".join([code[i : i + 2] for i in range(0, length, 2)])
        return code

    @staticmethod
    def format_token_for_display(token: str) -> str:
        """
        Format a token for better display and readability
        """
        # Add spaces or hyphens for long tokens
        if len(token) > 8:
            # Add hyphens every 4 characters
            formatted = "-".join([token[i : i + 4] for i in range(0, len(token), 4)])
            return formatted
        return token


    @staticmethod
    def validate_token_format(token: str, expected_length: int = None) -> bool:
        """
        Validate that a token matches expected format

        FIXED: Now accepts ALL alphanumeric characters (A-Z, 0-9)
        Previously excluded: 0, O, I, l, 1 (which was too restrictive)
    """
        if not token:
            return False

        # Remove hyphens and spaces for validation
        clean_token = token.replace("-", "").replace(" ", "").upper()

        # Check length if specified
        if expected_length and len(clean_token) != expected_length:
            return False

        # Accept ALL alphanumeric characters (A-Z, 0-9)
        # This is more permissive than the previous SAFE_CHARS restriction
        return clean_token.isalnum()

    @staticmethod
    def validate_token_format_strict(token: str, expected_length: int = None) -> bool:
        """
        Strict validation - only for newly generated tokens (optional)
        Uses SAFE_CHARS (excludes confusing characters: 0, O, I, l, 1)
        """
        if not token:
            return False

        clean_token = token.replace("-", "").replace(" ", "").upper()

        if expected_length and len(clean_token) != expected_length:
            return False

        # Check if token contains only SAFE characters
        valid_chars = set(FriendlyTokenGenerator.SAFE_CHARS.upper())
        return all(c in valid_chars for c in clean_token)


    @staticmethod
    def validate_token_format_permissive(token: str, expected_length: int = None) -> bool:
        """
        Permissive validation - for user-submitted tokens
        Accepts any alphanumeric characters
        """
        if not token:
            return False

        clean_token = token.replace("-", "").replace(" ", "").upper()

        if expected_length and len(clean_token) != expected_length:
            return False

        return clean_token.isalnum()


class SessionManager:
    """Session management with device fingerprinting"""

    @staticmethod
    def normalize_header(header_value: str) -> str:
        """Normalize header values by removing extra whitespace and converting to lowercase"""
        if not header_value:
            return ""
        return " ".join(header_value.strip().lower().split())

    @staticmethod
    def extract_client_ip(request: Request) -> str:
        """Extract client IP with comprehensive proxy support"""
        # Check for various proxy headers in order of preference
        ip_headers = [
            "cf-connecting-ip",  # Cloudflare
            "x-real-ip",  # Nginx
            "x-forwarded-for",  # Standard proxy header
            "x-client-ip",  # Alternative
            "x-cluster-client-ip",  # Kubernetes
        ]

        for header in ip_headers:
            ip_value = request.headers.get(header)
            if ip_value:
                # Handle comma-separated IPs (take the first one)
                first_ip = ip_value.split(",")[0].strip()
                # Validate IP format
                try:
                    ipaddress.ip_address(first_ip)
                    return first_ip
                except ValueError:
                    continue

        # Fallback to request client
        return str(request.client.host) if request.client else "unknown"

    @staticmethod
    def parse_user_agent_simple(user_agent: str) -> dict:
        """Simple user agent parsing without external dependencies"""
        if not user_agent:
            return {
                "browser": "unknown",
                "os": "unknown",
                "device_type": "unknown",
                "is_mobile": False,
                "is_bot": True,
            }

        ua_lower = user_agent.lower()

        # Browser detection
        browsers = {
            "chrome": ["chrome", "crios"],
            "firefox": ["firefox", "fxios"],
            "safari": ["safari"],
            "edge": ["edge", "edg"],
            "opera": ["opera", "opr"],
            "internet_explorer": ["trident", "msie"],
        }

        browser = "unknown"
        for browser_name, patterns in browsers.items():
            if any(pattern in ua_lower for pattern in patterns):
                browser = browser_name
                break

        # OS detection
        operating_systems = {
            "windows": ["windows", "win32", "win64"],
            "macos": ["mac os", "darwin"],
            "linux": ["linux", "ubuntu", "debian"],
            "android": ["android"],
            "ios": ["iphone", "ipad", "ipod"],
        }

        os = "unknown"
        for os_name, patterns in operating_systems.items():
            if any(pattern in ua_lower for pattern in patterns):
                os = os_name
                break

        # Device type detection
        is_mobile = any(term in ua_lower for term in ["mobile", "android", "iphone"])
        is_tablet = any(term in ua_lower for term in ["tablet", "ipad"])

        if is_tablet:
            device_type = "tablet"
        elif is_mobile:
            device_type = "mobile"
        else:
            device_type = "desktop"

        # Bot detection
        bot_indicators = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "curl",
            "wget",
            "python",
            "java",
            "axios",
            "node",
            "phantom",
            "selenium",
            "headless",
            "automated",
            "monitor",
            "test",
        ]
        is_bot = any(indicator in ua_lower for indicator in bot_indicators)

        return {
            "browser": browser,
            "os": os,
            "device_type": device_type,
            "is_mobile": is_mobile,
            "is_tablet": is_tablet,
            "is_bot": is_bot,
        }

    @staticmethod
    def calculate_device_risk_score(device_data: dict) -> tuple[int, list]:
        """Calculate risk score based on device characteristics"""
        risk_score = 0
        risk_factors = []

        # Missing or suspicious user agent
        if not device_data.get("user_agent") or device_data.get("parsed_ua", {}).get(
            "is_bot"
        ):
            risk_score += 40
            risk_factors.append("suspicious_user_agent")

        # Missing standard browser headers
        if not device_data.get("accept_language"):
            risk_score += 25
            risk_factors.append("missing_accept_language")

        if not device_data.get("accept_encoding"):
            risk_score += 20
            risk_factors.append("missing_accept_encoding")

        # Check for automation tools in user agent
        user_agent = device_data.get("user_agent", "").lower()
        automation_indicators = [
            "selenium",
            "webdriver",
            "phantom",
            "headless",
            "automated",
        ]
        if any(indicator in user_agent for indicator in automation_indicators):
            risk_score += 50
            risk_factors.append("automation_detected")

        # Suspicious IP patterns
        client_ip = device_data.get("client_ip", "")
        if client_ip in ["unknown", "127.0.0.1", "localhost"] or not client_ip:
            risk_score += 15
            risk_factors.append("suspicious_ip")

        # Check for common VPN/proxy patterns
        vpn_indicators = ["vpn", "proxy", "tor"]
        headers_str = " ".join(
            [
                device_data.get("user_agent", ""),
                device_data.get("accept_language", ""),
                device_data.get("accept_encoding", ""),
            ]
        ).lower()

        if any(indicator in headers_str for indicator in vpn_indicators):
            risk_score += 30
            risk_factors.append("proxy_detected")

        return min(risk_score, 100), risk_factors

    @staticmethod
    async def create_session(
        db: AsyncSession,
        user_id: UUID,
        request: Request,
        login_method: str = "password",
    ) -> VotingSession:
        """Create a new user session with enhanced tracking - NOW WITH 10 MINUTE EXPIRATION"""

        # Extract device information
        device_info = SessionManager.extract_device_info(request)

        # CHANGED: All sessions now last 10 minutes
        session_duration = timedelta(minutes=10)
    
        # Generate a unique session ID first
        session_id = uuid4()

        # Create a proper JWT token for the session
        # This token will be used in the Authorization header and voting_session cookie
        session_token = TokenManager.create_access_token(
            data={
                "sub": str(user_id),
                "type": "voting_session",  # This matches your middleware check
                "session_id": str(session_id),
                "device_fingerprint": device_info.get("fingerprint"),
                "login_method": login_method,
            },
            expires_delta=session_duration,
            session_id=session_id
        )

        # Create the session record with the JWT token
        session = VotingSession(
            id=session_id,  # Use the same ID we put in the JWT
            electorate_id=user_id,
            session_token=session_token,  # Now a proper JWT token instead of UUID
            device_fingerprint=device_info.get("fingerprint"),
            user_agent=device_info.get("user_agent"),
            user_agent_hash=hashlib.sha256(
                device_info.get("user_agent", "").encode()
            ).hexdigest()[:16],
            ip_address=device_info.get("client_ip"),
            login_method=login_method,
            expires_at=datetime.now(timezone.utc) + session_duration,
        )

        db.add(session)
        await db.commit()
        await db.refresh(session)

        return session

    @staticmethod
    async def validate_session(
        db: AsyncSession, session_id: UUID, request: Request
    ) -> Optional[VoterSession]:
        """Validate session and update activity"""

        result = await db.execute(
            select(VotingSession)
            .options(selectinload(VotingSession.electorate))
            .where(VotingSession.id == session_id)
        )
        session = result.scalar_one_or_none()

        if not session or not session.is_valid:
            return None

        # Update activity and perform security checks
        current_ip = (
            getattr(request.client, "host", "unknown") if request.client else "unknown"
        )
        session.update_activity(current_ip)

        # Security monitoring
        if session.ip_address != current_ip:

            session.mark_suspicious("ip_change")

        await db.commit()
        return session

    @staticmethod
    async def terminate_session(
        db: AsyncSession, session_id: UUID, reason: str = "logout"
    ) -> bool:
        """Terminate a specific session"""

        result = await db.execute(
            select(VotingSession).where(VotingSession.id == session_id)
        )
        session = result.scalar_one_or_none()

        if session:
            session.terminate(reason)
            await db.commit()

            return True

        return False

    @staticmethod
    def extract_device_info(request: Request) -> dict:
        """
        Extract comprehensive device fingerprinting information for robust authentication

        Enhanced version of your original method that maintains compatibility
        while adding security features and better error handling.
        """
        # Extract basic headers (same as original)
        user_agent = request.headers.get("user-agent", "").strip()
        accept_language = request.headers.get("accept-language", "").strip()
        accept_encoding = request.headers.get("accept-encoding", "").strip()

        # Get client IP with enhanced proxy support
        client_ip = SessionManager.extract_client_ip(request)

        # Parse user agent for additional insights
        parsed_ua = SessionManager.parse_user_agent_simple(user_agent)

        # Extract additional security-relevant headers
        security_headers = {
            "connection": request.headers.get("connection", ""),
            "cache_control": request.headers.get("cache-control", ""),
            "sec_ch_ua": request.headers.get("sec-ch-ua", ""),
            "sec_ch_ua_platform": request.headers.get("sec-ch-ua-platform", ""),
            "sec_ch_ua_mobile": request.headers.get("sec-ch-ua-mobile", ""),
            "sec_fetch_site": request.headers.get("sec-fetch-site", ""),
            "sec_fetch_mode": request.headers.get("sec-fetch-mode", ""),
            "dnt": request.headers.get("dnt", ""),
        }

        # Normalize language for consistency (take primary language only)
        normalized_language = (
            accept_language.split(",")[0].split(";")[0].lower()
            if accept_language
            else ""
        )
        normalized_encoding = SessionManager.normalize_header(accept_encoding)

        # Fingerprint device (more stable components)
        components = [
            parsed_ua.get("browser", ""),
            parsed_ua.get("os", ""),
            normalized_language,
            normalized_encoding,
            (
                client_ip
                if not client_ip.startswith(("127.", "192.168.", "10.", "172."))
                else ""
            ),
        ]

        fingerprint_data = "|".join(filter(None, components))
        fingerprint = hashlib.sha256(fingerprint_data.encode("utf-8")).hexdigest()[:32]

        # 3. Security fingerprint (includes security headers)
        security_components = components + [
            security_headers.get("sec_ch_ua", ""),
            security_headers.get("sec_ch_ua_platform", ""),
            security_headers.get("connection", ""),
        ]

        security_fingerprint_data = "|".join(filter(None, security_components))
        security_fingerprint = hashlib.sha256(
            security_fingerprint_data.encode("utf-8")
        ).hexdigest()[:32]

        # Compile device information
        device_data = {
            # Original fields for backward compatibility
            "user_agent": user_agent,
            "accept_language": accept_language,
            "accept_encoding": accept_encoding,
            # Enhanced fields
            "client_ip": client_ip,
            "fingerprint": fingerprint,
            "security_fingerprint": security_fingerprint,
            "parsed_ua": parsed_ua,
            "normalized_language": normalized_language,
            "normalized_encoding": normalized_encoding,
            "security_headers": security_headers,
            "timestamp": datetime.now(timezone.utc).timestamp(),
            # Fingerprint metadata
            "fingerprint_components": len([c for c in components if c]),
            "has_security_headers": bool(any(security_headers.values())),
        }

        # Calculate risk assessment
        risk_score, risk_factors = SessionManager.calculate_device_risk_score(
            device_data
        )
        device_data.update(
            {
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "risk_level": (
                    "high"
                    if risk_score >= 70
                    else "medium" if risk_score >= 30 else "low"
                ),
            }
        )

        return device_data


class TokenManager:
    """Enhanced token management with session integration"""

    # @staticmethod
    # def create_access_token(
    #     data: dict,
    #     expires_delta: Optional[timedelta] = None,
    #     session_id: Optional[UUID] = None,
    # ) -> str:
    #     """
    #     Create a JWT access token with optional session reference
    #     CHANGED: Default expiration is now 10 minutes for voting sessions
    #     FIXED: Respects token type from data parameter
    #     """

    #     to_encode = data.copy()
    #     expire = datetime.now(timezone.utc) + (
    #         expires_delta or timedelta(minutes=10)  # CHANGED: Default to 10 minutes
    #     )
        
    #     # Add expiration and issued-at timestamp
    #     to_encode.update({
    #         "exp": expire,
    #         "iat": datetime.now(timezone.utc),
    #     })
        
    #     # Only set default type if not provided in data
    #     if "type" not in to_encode:
    #         to_encode["type"] = "access"

    #     # Include session ID if provided
    #     if session_id:
    #         to_encode["sid"] = str(session_id)

    #     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    @staticmethod
    def create_access_token(
        data: dict,
        expires_delta: Optional[timedelta] = None,
        session_id: Optional[UUID] = None,
    ) -> str:
        """
        Create a JWT access token with optional session reference
        CHANGED: Default expiration is now 10 minutes for voting sessions
        FIXED: Respects token type from data parameter
        """
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(minutes=10)
        )
    
        # Add expiration and issued-at timestamp
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
        })
    
        # Only set default type if not provided in data
        if "type" not in to_encode:
            to_encode["type"] = "access"

        # Include session ID if provided (use "session_id" not "sid" for consistency)
        if session_id and "session_id" not in to_encode:
            to_encode["session_id"] = str(session_id)

        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def create_voting_token(
        user_id: UUID, device_info: str = None, ip_address: str = None
    ) -> str:
        """Create a user-friendly voting token"""

        # Generate a friendly token instead of JWT
        # Use alphanumeric code format: AB12-CD34-EF56
        friendly_token = FriendlyTokenGenerator.generate_alphanumeric_code(length=8)

        # Return friendly token (storage hashing is handled by CRUD functions)
        return friendly_token

    @staticmethod
    def decode_token(token: str) -> dict:
        """Decode and verify a JWT token"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError as e:
            raise ValueError("Invalid or expired token") from e

    @staticmethod
    async def create_voting_token_record(
        db: AsyncSession,
        user_id: uuid.UUID,
        token: str,
        device_info: str,
        ip_address: str,
    ):
        """Create voting token record with absolute expiration"""
        from app.models.electorates import VotingToken

        current_time = datetime.now(timezone.utc)
        absolute_expiry = current_time + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        regular_expiry = current_time + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        # Normalize token before hashing (remove hyphens/spaces and uppercase)
        clean_token = token.replace("-", "").replace(" ", "").upper()
        token_hash = hashlib.sha256(clean_token.encode()).hexdigest()

        refresh_token_record = VotingToken(
            user_id=user_id,
            token_hash=token_hash,
            device_info=device_info,
            ip_address=ip_address,
            expires_at=regular_expiry,
            absolute_expires_at=absolute_expiry,
            last_used_at=current_time,
            usage_count=1,
            revoked=False,
        )

        db.add(refresh_token_record)
        await db.commit()
        await db.refresh(refresh_token_record)

        return refresh_token_record

    @staticmethod
    async def validate_voting_token(db: AsyncSession, token: str):
        """Validate refresh token with absolute expiration check"""
        from app.models.electorates import VotingToken
        from sqlalchemy.orm import selectinload

        # Normalize token before hashing for lookup
        clean_token = token.replace("-", "").replace(" ", "").upper()
        token_hash = hashlib.sha256(clean_token.encode()).hexdigest()

        result = await db.execute(
            select(VotingToken)
            .options(selectinload(VotingToken.electorate))
            .where(VotingToken.token_hash == token_hash, VotingToken.revoked == False)
        )

        return result.scalar_one_or_none()

    @staticmethod
    async def revoke_voting_token(db: AsyncSession, token_id: uuid.UUID):
        """Revoke a refresh token by ID"""
        from app.models.electorates import VotingToken

        result = await db.execute(select(VotingToken).where(VotingToken.id == token_id))

        token_record = result.scalar_one_or_none()
        if token_record:
            token_record.revoke()
            await db.commit()
            return True
        return False


def set_token_cookie(response: Response, voter_token: str, request: Request = None):
    """Helper function to set refresh token cookie with proper security settings"""
    
    # Determine if we're using HTTPS
    is_secure = IS_PRODUCTION
    if request:
        is_secure = request.url.scheme == "https" or IS_PRODUCTION
    
    # For development (localhost), use lax
    # For production (HTTPS), use none to allow cross-site
    samesite_setting = "none" if is_secure else "lax"
    
    print(f"Setting cookie - Secure: {is_secure}, SameSite: {samesite_setting}")
    
    response.set_cookie(
        key="refresh_token",
        value=voter_token,
        httponly=True,
        secure=is_secure,
        samesite=samesite_setting,
        max_age=60 * 60 * 24 * REFRESH_TOKEN_EXPIRE_DAYS,
        domain=None,  # Let browser determine domain
        path="/",  # Available for all paths
    )


def hash_password(password: str) -> str:
    """Hash password using Argon2"""
    if not password:
        raise ValueError("Password cannot be empty")
    return ph.hash(password)


def verify_password(stored_hash: str, plain_password: str) -> bool:
    """
    Verify password against stored hash

    Args:
        stored_hash: The Argon2 hash from storage (e.g., from .env)
        plain_password: The plain text password to verify

    Returns:
        True if password matches, False otherwise
    """
    try:
        # Argon2 verify expects (hash, password)
        ph.verify(stored_hash, plain_password)
        return True
    except Exception:
        return False


def verify_pin(voting_pin: str, stored_hash: str) -> bool:
    """Verify voting PIN against stored hash"""
    return verify_password(stored_hash, voting_pin)
