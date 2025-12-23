"""
Configuration settings for the Election System
Supports development and production environments with security middlewares
"""

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import List, Optional
import secrets
import os
from enum import Enum


class Environment(str, Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings with environment-specific configurations"""

    # Application Info
    APP_NAME: str = "University Election System"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Secure rental election system for universities"
    API_PREFIX: str = "/api"

    # Environment
    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    DEBUG: bool = True
    TESTING: bool = False

    # Server Configuration
    HOST: str = "0.0.0.0"  # Allow connections from local network
    PORT: int = 8000
    WORKERS: int = 1
    RELOAD: bool = True

    # Admin Credentials
    # ADMIN_USERS: Optional[str] = None
    EC_OFFICIAL_USERS: Optional[str] = None
    POLLING_AGENT_USERS: Optional[str] = None
    ADMIN_PASSWORD_HASH: Optional[str] = None
    ADMIN_PERMISSIONS: Optional[str] = None
    ENFORCE_DEVICE_FINGERPRINT: bool = False

    # SMTP/Email Settings
    SMTP_SERVER: str = Field(
        default="smtp.gmail.com", description="SMTP server address"
    )
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    # SMTP_USERNAME: str = Field(default="", description="SMTP username/email")
    # SMTP_PASSWORD: str = Field(default="", description="SMTP password/app password")
    FROM_EMAIL: str = Field(
        default="noreply@voting-system.com", description="From email address"
    )
    FROM_NAME: str = Field(
        default="Election System", description="From name for emails"
    )

    # SMS Settings (Optional)
    SMS_PROVIDER: str = Field(
        default="twilio", description="SMS provider (twilio, africastalking, etc.)"
    )
    SMS_API_KEY: Optional[str] = Field(default=None, description="SMS API key")
    SMS_API_SECRET: Optional[str] = Field(default=None, description="SMS API secret")
    SMS_FROM_NUMBER: Optional[str] = Field(default=None, description="SMS from number")
    SMS_ENABLED: bool = Field(default=False, description="Enable SMS notifications")

    # Security
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Password Security
    PWD_MIN_LENGTH: int = 8
    PWD_MAX_LENGTH: int = 128
    PWD_REQUIRE_UPPERCASE: bool = True
    PWD_REQUIRE_LOWERCASE: bool = True
    PWD_REQUIRE_NUMBERS: bool = True
    PWD_REQUIRE_SPECIAL: bool = False

    # Database
    DATABASE_URL: str = (
        "postgresql+asyncpg://election_user:election_pass@localhost:5432/election_db"
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_POOL_RECYCLE: int = 3600
    DATABASE_ECHO: bool = False  # Set to True for SQL logging in development

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    REDIS_SOCKET_CONNECT_TIMEOUT: int = 5
    REDIS_HEALTH_CHECK_INTERVAL: int = 30

    # CORS Settings
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://192.168.1.*",
        "http://10.0.0.*",
    ]
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    ALLOWED_HEADERS: List[str] = ["*"]
    ALLOW_CREDENTIALS: bool = True

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 3600  # 1 hour in seconds
    RATE_LIMIT_PER_IP: int = 1000  # Per IP address
    RATE_LIMIT_AUTH_REQUESTS: int = 5  # Login attempts per window
    RATE_LIMIT_AUTH_WINDOW: int = 900  # 15 minutes
    RATE_LIMIT_VOTE_REQUESTS: int = 10  # Vote attempts per window
    RATE_LIMIT_VOTE_WINDOW: int = 60  # 1 minute

    # File Upload
    MAX_FILE_SIZE: int = 5 * 1024 * 1024  # 5MB
    ALLOWED_FILE_TYPES: List[str] = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "text/csv",
        "application/vnd.ms-excel",
    ]
    UPLOAD_DIR: str = "uploads"
    STATIC_DIR: str = "static"

    # SSL/TLS Configuration
    SSL_CERT_PATH: Optional[str] = None
    SSL_KEY_PATH: Optional[str] = None
    SSL_ENABLED: bool = False

    # Session Configuration
    SESSION_EXPIRE_MINUTES: int = 60
    SESSION_COOKIE_NAME: str = "election_session"
    SESSION_COOKIE_SECURE: bool = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE: Optional[str] = None
    LOG_ROTATION: str = "1 day"
    LOG_RETENTION: str = "30 days"
    LOG_MAX_SIZE: str = "10 MB"

    # Election-Specific Settings
    MAX_ELECTIONS_PER_UNIVERSITY: int = 10
    MAX_CANDIDATES_PER_ELECTION: int = 50
    MAX_VOTERS_PER_ELECTION: int = 10000
    VOTING_PIN_LENGTH: int = 6
    VOTING_PIN_EXPIRY_HOURS: int = 24

    # Audit & Compliance
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_LEVEL: str = "INFO"
    GDPR_COMPLIANCE: bool = True
    DATA_RETENTION_DAYS: int = 365

    # Email Configuration (for notifications)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    EMAIL_FROM: Optional[str] = None

    # Monitoring & Health Checks
    HEALTH_CHECK_ENABLED: bool = True
    METRICS_ENABLED: bool = True
    MONITORING_ENDPOINT: str = "/health"

    # Backup Configuration
    BACKUP_ENABLED: bool = True
    BACKUP_INTERVAL_HOURS: int = 6
    BACKUP_RETENTION_DAYS: int = 30
    BACKUP_ENCRYPTION_KEY: Optional[str] = None

    @field_validator("ENVIRONMENT", mode="before")
    def validate_environment(cls, v):
        if isinstance(v, str):
            return Environment(v.lower())
        return v

    @field_validator("SECRET_KEY", mode="before")
    def validate_secret_key(cls, v, values):
        if not v or v == "your-secret-key-change-this":
            if values.data.get("ENVIRONMENT") == Environment.PRODUCTION:
                raise ValueError("SECRET_KEY must be set for production")
            return secrets.token_urlsafe(32)
        return v

    @field_validator("DATABASE_URL", mode="before")
    def validate_database_url(cls, v, values):
        if (
            "localhost" in v
            and values.data.get("ENVIRONMENT") == Environment.PRODUCTION
        ):
            print("Warning: Using localhost database in production")
        return v

    @field_validator("ALLOWED_ORIGINS", mode="before")
    def validate_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == Environment.DEVELOPMENT

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == Environment.PRODUCTION

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == Environment.TESTING

    @property
    def database_url_sync(self) -> str:
        """Synchronous database URL for Alembic migrations"""
        return self.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

    @property
    def cors_origins(self) -> List[str]:
        """Processed CORS origins for middleware"""
        origins = []
        for origin in self.ALLOWED_ORIGINS:
            if "*" in origin:
                # Handle wildcard patterns for local networks
                origins.append(origin)
            else:
                origins.append(origin)
        return origins

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


# Development Settings
class DevelopmentSettings(Settings):
    """Development environment settings"""

    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    DEBUG: bool = True
    RELOAD: bool = True
    DATABASE_ECHO: bool = True  # Show SQL queries
    LOG_LEVEL: str = "DEBUG"

    # Relaxed security for development
    CORS_ALLOW_ALL_ORIGINS: bool = True
    SESSION_COOKIE_SECURE: bool = False

    # Development database
    DATABASE_URL: str = (
        "postgresql+asyncpg://election_user:election_pass@localhost:5432/election_dev_db"
    )


# Production Settings
class ProductionSettings(Settings):
    """Production environment settings"""

    ENVIRONMENT: Environment = Environment.PRODUCTION
    DEBUG: bool = False
    RELOAD: bool = False
    DATABASE_ECHO: bool = False
    LOG_LEVEL: str = "WARNING"

    # Strict security for production
    SESSION_COOKIE_SECURE: bool = True
    SSL_ENABLED: bool = True

    # Production database with connection pooling
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 50

    # Strict CORS
    ALLOWED_ORIGINS: List[str] = []  # Must be explicitly set

    # Enhanced rate limiting
    RATE_LIMIT_REQUESTS: int = 50
    RATE_LIMIT_AUTH_REQUESTS: int = 3

    @field_validator("SECRET_KEY")
    def secret_key_required(cls, v):
        if not v or len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters in production")
        return v


# Testing Settings
class TestingSettings(Settings):
    """Testing environment settings"""

    ENVIRONMENT: Environment = Environment.TESTING
    DEBUG: bool = True
    TESTING: bool = True
    DATABASE_URL: str = "sqlite+aiosqlite:///./test_election.db"
    REDIS_URL: str = "redis://localhost:6379/15"  # Separate test Redis DB


# Factory function to get settings based on environment
def get_settings() -> Settings:
    """Get settings based on environment variable"""
    env = os.getenv("ENVIRONMENT", "development").lower()

    if env == "production":
        return ProductionSettings()
    elif env == "testing":
        return TestingSettings()
    else:
        return DevelopmentSettings()


# Global settings instance
settings = get_settings()

# Security Middleware Configuration
SECURITY_MIDDLEWARE_CONFIG = {
    "trustedhost": {
        "allowed_hosts": ["localhost", "127.0.0.1", "192.168.1.*", "10.0.0.*"],
        "force_https": settings.is_production,
    },
    "httpsredirect": {
        "enabled": settings.is_production,
    },
    "gzip": {
        "minimum_size": 1000,
        "enabled": True,
    },
    "session": {
        "secret_key": settings.SECRET_KEY,
        "session_cookie": settings.SESSION_COOKIE_NAME,
        "max_age": settings.SESSION_EXPIRE_MINUTES * 60,
        "same_site": settings.SESSION_COOKIE_SAMESITE,
        "https_only": settings.SESSION_COOKIE_SECURE,
    },
}

# Rate Limiting Configuration
RATE_LIMIT_CONFIG = {
    "default": f"{settings.RATE_LIMIT_REQUESTS}/{settings.RATE_LIMIT_WINDOW}",
    "auth": f"{settings.RATE_LIMIT_AUTH_REQUESTS}/{settings.RATE_LIMIT_AUTH_WINDOW}",
    "voting": f"{settings.RATE_LIMIT_VOTE_REQUESTS}/{settings.RATE_LIMIT_VOTE_WINDOW}",
    "per_ip": f"{settings.RATE_LIMIT_PER_IP}/{settings.RATE_LIMIT_WINDOW}",
}

# Logging Configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": settings.LOG_FORMAT,
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": settings.LOG_LEVEL,
            "formatter": "default",
            "stream": "ext://sys.stdout",
        },
        "file": (
            {
                "class": "logging.handlers.RotatingFileHandler",
                "level": settings.LOG_LEVEL,
                "formatter": "detailed",
                "filename": settings.LOG_FILE or "election_system.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
            }
            if settings.LOG_FILE
            else None
        ),
    },
    "loggers": {
        "election_system": {
            "level": settings.LOG_LEVEL,
            "handlers": ["console"] + (["file"] if settings.LOG_FILE else []),
            "propagate": False,
        },
        "uvicorn": {
            "level": "INFO",
            "handlers": ["console"],
            "propagate": False,
        },
        "sqlalchemy.engine": {
            "level": "INFO" if settings.DATABASE_ECHO else "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
    },
    "root": {
        "level": settings.LOG_LEVEL,
        "handlers": ["console"] + (["file"] if settings.LOG_FILE else []),
    },
}

# Remove None handlers
if LOGGING_CONFIG["handlers"]["file"] is None:
    del LOGGING_CONFIG["handlers"]["file"]

# Export commonly used settings
__all__ = [
    "settings",
    "Settings",
    "DevelopmentSettings",
    "ProductionSettings",
    "TestingSettings",
    "get_settings",
    "SECURITY_MIDDLEWARE_CONFIG",
    "RATE_LIMIT_CONFIG",
    "LOGGING_CONFIG",
]
