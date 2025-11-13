from sqlalchemy import (
    String,
    Integer,
    Boolean,
    TIMESTAMP,
    func,
    Text,
    Float,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base
from datetime import datetime, timezone
import uuid
from typing import Optional, Dict, Any


class Electorate(Base):
    __tablename__ = "students"
    __table_args__ = (
        # Index for fast lookup, especially for authentication
        {"sqlite_autoincrement": True},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    student_id: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    program: Mapped[str] = mapped_column(String(100), nullable=True)
    year_level: Mapped[int] = mapped_column(Integer, nullable=True)
    phone_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    # Store hashed voting_pin for security
    voting_pin_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    # Store device fingerprint for anti-impersonation
    device_fingerprint: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    has_voted: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, index=True
    )
    voted_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_banned: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    # Relationships
    voting_tokens: Mapped[list["VotingToken"]] = relationship(
        "VotingToken", back_populates="electorate"
    )
    device_registrations: Mapped[list["DeviceRegistration"]] = relationship(
        "DeviceRegistration", back_populates="electorate"
    )
    voting_sessions: Mapped[list["VotingSession"]] = relationship(
        "VotingSession", back_populates="electorate"
    )

    @property
    def get_token_hash(self):
        """Get the most recent active voting token hash for this electorate"""
        if self.voting_tokens:
            # Find the most recent active token
            active_tokens = [
                token
                for token in self.voting_tokens
                if not token.revoked and token.is_active
            ]
            if active_tokens:
                return active_tokens[-1].token_hash
        return None


class VotingToken(Base):
    __tablename__ = "voting_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    electorate_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("students.id"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    device_fingerprint: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    device_info: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    location_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    biometric_data_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_password_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    usage_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    revoked_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Relationships
    electorate: Mapped["Electorate"] = relationship(
        "Electorate", back_populates="voting_tokens"
    )


class DeviceRegistration(Base):
    __tablename__ = "device_registrations"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    device_fingerprint: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    location_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=True)
    device_info: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    registration_link_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("registration_links.id"), nullable=True, index=True
    )
    electorate_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("students.id"), nullable=True, index=True
    )
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    biometric_data_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_password_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_banned: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ban_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ban_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )

    # Relationships
    registration_link: Mapped["RegistrationLink"] = relationship(
        "RegistrationLink", back_populates="devices"
    )
    electorate: Mapped[Optional["Electorate"]] = relationship(
        "Electorate", back_populates="device_registrations"
    )


class RegistrationLink(Base):
    __tablename__ = "registration_links"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    link_token: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    max_devices: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    current_device_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=True
    )

    # Relationships
    devices: Mapped[list["DeviceRegistration"]] = relationship(
        "DeviceRegistration", back_populates="registration_link"
    )


class VotingSession(Base):
    __tablename__ = "voting_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    electorate_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("students.id"), nullable=False, index=True
    )
    session_token: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    device_fingerprint: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    user_agent_hash: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    login_method: Mapped[str] = mapped_column(String(50), nullable=False)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_activity_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    terminated_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    termination_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    suspicious_activity: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    activity_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    electorate: Mapped["Electorate"] = relationship(
        "Electorate", back_populates="voting_sessions"
    )

    def update_activity(self, current_ip: str):
        """Update session activity and IP address"""
        self.last_activity_at = datetime.now(timezone.utc)
        self.activity_count += 1

        # Check for IP changes
        if self.ip_address != current_ip:
            self.suspicious_activity = True

    def terminate(self, reason: str = "logout"):
        """Terminate the session"""
        self.is_valid = False
        self.terminated_at = datetime.now(timezone.utc)
        self.termination_reason = reason


class Portfolio(Base):
    __tablename__ = "portfolios"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_candidates: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    voting_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    candidates: Mapped[list["Candidate"]] = relationship(
        "Candidate", back_populates="portfolio", cascade="all, delete-orphan"
    )
    votes: Mapped[list["Vote"]] = relationship(
        "Vote", back_populates="portfolio", cascade="all, delete-orphan"
    )


class Candidate(Base):
    __tablename__ = "candidates"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    portfolio_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("portfolios.id"), 
        nullable=False, 
        index=True
    )
    picture_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    picture_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    manifesto: Mapped[str | None] = mapped_column(Text, nullable=True)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    display_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    portfolio: Mapped["Portfolio"] = relationship(
        "Portfolio", 
        back_populates="candidates",
        lazy="selectin"
    )
    votes: Mapped[list["Vote"]] = relationship(
        "Vote", back_populates="candidate", cascade="all, delete-orphan"
    )


class Vote(Base):
    __tablename__ = "votes"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    electorate_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("students.id"), nullable=False, index=True
    )
    portfolio_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("portfolios.id"), nullable=False, index=True
    )
    candidate_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("candidates.id"), nullable=False, index=True
    )
    voting_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("voting_sessions.id"), nullable=True, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    device_fingerprint: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    voted_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    electorate: Mapped["Electorate"] = relationship("Electorate")
    portfolio: Mapped["Portfolio"] = relationship("Portfolio", back_populates="votes")
    candidate: Mapped["Candidate"] = relationship("Candidate", back_populates="votes")
    voting_session: Mapped[Optional["VotingSession"]] = relationship("VotingSession")
