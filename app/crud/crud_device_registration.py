"""
CRUD operations for DeviceRegistration and RegistrationLink models
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func
from sqlalchemy.orm import selectinload
from app.models.electorates import DeviceRegistration, RegistrationLink
from app.schemas.electorates import DeviceRegistrationRequest, RegistrationLinkCreate
from typing import List, Optional
import uuid
import hashlib
import os
import logging
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from app.utils.clean_json import clean_json_data


# DeviceRegistration CRUD operations


async def create_device_registration(
    db: AsyncSession,
    registration_data: DeviceRegistrationRequest,
    device_fingerprint: str,
    device_info: dict,
    ip_address: str,
    user_agent: str,
    registration_link_id: uuid.UUID,
    electorate_id: Optional[uuid.UUID] = None,
) -> DeviceRegistration:
    """Create a new device registration record (full registration flow)"""

    # Hash biometric data and device password if provided
    biometric_hash = None
    if registration_data.biometric_data:
        biometric_hash = hashlib.sha256(
            registration_data.biometric_data.encode()
        ).hexdigest()

    device_password_hash = None
    if registration_data.device_password:
        device_password_hash = hashlib.sha256(
            registration_data.device_password.encode()
        ).hexdigest()

    cleaned_device_info = clean_json_data(device_info)
    cleaned_location_data = None

    if registration_data.location:
        cleaned_location_data = clean_json_data(registration_data.location)

    db_registration = DeviceRegistration(
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
        location_data=cleaned_location_data,
        device_info=cleaned_device_info,
        user_agent=user_agent,
        registration_link_id=registration_link_id,
        electorate_id=electorate_id,
        full_name=registration_data.full_name,
        biometric_data_hash=biometric_hash,
        device_password_hash=device_password_hash,
        last_attempt_at=None,
    )

    db.add(db_registration)
    await db.commit()
    await db.refresh(db_registration)
    return db_registration


async def create_device_registration_simple(
    db: AsyncSession,
    device_fingerprint: str,
    device_info: dict,
    electorate_id: uuid.UUID,
) -> DeviceRegistration:
    """
    Create a simplified device registration (for auto-registration during token verification)

    This is used when a voter uses their admin-generated token for the first time.
    Creates or uses a default "auto-registration" link.
    """

    # Get or create a default registration link for auto-registrations
    default_link = await get_or_create_auto_registration_link(db)

    # Get electorate's full name from the database
    from sqlalchemy.future import select
    from app.models.electorates import Electorate

    result = await db.execute(select(Electorate).where(Electorate.id == electorate_id))
    electorate = result.scalar_one_or_none()

    # Use electorate student_id as full_name or default
    full_name = electorate.student_id if electorate else "Auto-registered User"

    cleaned_device_info = clean_json_data(device_info)

    db_registration = DeviceRegistration(
        device_fingerprint=device_fingerprint,
        ip_address=device_info.get("client_ip", "unknown"),
        location_data=device_info.get("location"),
        device_info=cleaned_device_info,
        user_agent=device_info.get("user_agent", "unknown"),
        registration_link_id=default_link.id,  # Use default link
        electorate_id=electorate_id,
        full_name=full_name,  # Use student_id or default name
        biometric_data_hash=None,
        device_password_hash=None,
        is_banned=False,
        ban_reason=None,
        ban_count=0,
        last_attempt_at=None,
    )

    db.add(db_registration)
    await db.commit()
    await db.refresh(db_registration)
    return db_registration


async def get_or_create_auto_registration_link(db: AsyncSession) -> RegistrationLink:
    """
    Get or create a permanent registration link for auto-registrations
    This link is used when devices are auto-registered during token verification
    """
    # Use a fixed token for the auto-registration link
    AUTO_REGISTRATION_TOKEN = "auto_registration_system"

    # Try to get existing link
    result = await db.execute(
        select(RegistrationLink).where(
            RegistrationLink.link_token == AUTO_REGISTRATION_TOKEN
        )
    )
    link = result.scalar_one_or_none()

    if link:
        return link

    # Create new auto-registration link
    link = RegistrationLink(
        link_token=AUTO_REGISTRATION_TOKEN,
        max_devices=999999,  # Unlimited
        expires_at=datetime(2099, 12, 31, tzinfo=timezone.utc),  # Far future
        created_by="system",
        description="Automatic device registration for admin-generated tokens",
        is_active=True,
    )

    db.add(link)
    await db.commit()
    await db.refresh(link)
    return link


async def get_device_registration_by_fingerprint(
    db: AsyncSession, device_fingerprint: str
) -> Optional[DeviceRegistration]:
    """Get device registration by fingerprint"""
    result = await db.execute(
        select(DeviceRegistration)
        .options(selectinload(DeviceRegistration.registration_link))
        .where(DeviceRegistration.device_fingerprint == device_fingerprint)
    )
    return result.scalar_one_or_none()


async def get_device_registration_by_token(
    db: AsyncSession, device_fingerprint: str
) -> Optional[DeviceRegistration]:
    """Get device registration by token"""
    result = await db.execute(
        select(DeviceRegistration)
        .options(selectinload(DeviceRegistration.registration_link))
        .where(DeviceRegistration.electorate == device_fingerprint)
    )
    return result.scalar_one_or_none()


async def get_device_registrations_by_link(
    db: AsyncSession, registration_link_id: uuid.UUID
) -> List[DeviceRegistration]:
    """Get all device registrations for a registration link"""
    result = await db.execute(
        select(DeviceRegistration)
        .where(DeviceRegistration.registration_link_id == registration_link_id)
        .order_by(DeviceRegistration.created_at.desc())
    )
    return result.scalars().all()


async def ban_device(
    db: AsyncSession, device_fingerprint: str, reason: str
) -> DeviceRegistration | None:
    """
    Ban a device and update ban count
    """
    try:
        result = await db.execute(
            select(DeviceRegistration).where(
                DeviceRegistration.device_fingerprint == device_fingerprint
            )
        )
        device = result.scalar_one_or_none()

        if device:
            device.is_banned = True
            device.ban_reason = reason
            device.ban_count += 1
            device.last_attempt_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(device)

        return True

    except Exception as e:
        await db.rollback()
        return False


async def unban_device(db: AsyncSession, device_fingerprint: str) -> bool:
    """Unban a device"""
    result = await db.execute(
        select(DeviceRegistration).where(
            DeviceRegistration.device_fingerprint == device_fingerprint
        )
    )
    device = result.scalar_one_or_none()

    if device:
        device.is_banned = False
        device.ban_reason = None
        await db.commit()
        return True

    return False


async def update_device_attempt(
    db: AsyncSession, device_fingerprint: str
) -> DeviceRegistration | None:
    """
    Update the last attempt timestamp for a device
    """
    try:
        result = await db.execute(
            select(DeviceRegistration).where(
                DeviceRegistration.device_fingerprint == device_fingerprint
            )
        )
        device = result.scalar_one_or_none()

        if device:
            # Increment ban_count for failed attempts
            device.ban_count += 1
            device.last_attempt_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(device)

        return device

    except Exception as e:
        await db.rollback()
        raise Exception(f"Failed to update device attempt: {str(e)}")


# RegistrationLink CRUD operations


async def create_registration_link(
    db: AsyncSession, link_data: RegistrationLinkCreate
) -> RegistrationLink:
    """Create a new registration link"""

    # Generate unique link token

    created_by = "superuser"
    link_token = hashlib.sha256(
        f"{created_by}:{datetime.now(timezone.utc).isoformat()}:{uuid.uuid4()}".encode()
    ).hexdigest()[:32]

    db_link = RegistrationLink(
        link_token=link_token,
        max_devices=link_data.max_devices,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=48),
        created_by=created_by,
        description=link_data.description,
    )
    db.add(db_link)
    await db.commit()
    await db.refresh(db_link)
    return db_link


async def get_registration_link_by_token(
    db: AsyncSession, link_token: str
) -> Optional[RegistrationLink]:
    """Get registration link by token"""
    result = await db.execute(
        select(RegistrationLink)
        .options(selectinload(RegistrationLink.devices))
        .where(RegistrationLink.link_token == link_token)
    )
    return result.scalar_one_or_none()


async def get_registration_link_by_id(
    db: AsyncSession, link_id: uuid.UUID
) -> Optional[RegistrationLink]:
    """Get registration link by ID"""
    result = await db.execute(
        select(RegistrationLink)
        .options(selectinload(RegistrationLink.devices))
        .where(RegistrationLink.id == link_id)
    )
    return result.scalar_one_or_none()


async def get_all_registration_links(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> List[RegistrationLink]:
    """Get all registration links"""
    result = await db.execute(
        select(RegistrationLink)
        .options(selectinload(RegistrationLink.devices))
        .offset(skip)
        .limit(limit)
        .order_by(RegistrationLink.created_at.desc())
    )
    return result.scalars().all()


async def update_device_count(
    db: AsyncSession, registration_link_id: uuid.UUID
) -> Optional[RegistrationLink]:
    """Update device count for a registration link"""
    result = await db.execute(
        select(RegistrationLink).where(RegistrationLink.id == registration_link_id)
    )
    link = result.scalar_one_or_none()

    if link:
        # Count current devices
        count_result = await db.execute(
            select(func.count(DeviceRegistration.id)).where(
                DeviceRegistration.registration_link_id == registration_link_id
            )
        )
        device_count = count_result.scalar()

        link.current_device_count = device_count
        await db.commit()
        await db.refresh(link)

    return link


async def deactivate_registration_link(
    db: AsyncSession, link_id: uuid.UUID, reason: str = "Manual deactivation"
) -> bool:
    """Deactivate a registration link"""
    result = await db.execute(
        select(RegistrationLink).where(RegistrationLink.id == link_id)
    )
    link = result.scalar_one_or_none()

    if link:
        link.is_active = False
        await db.commit()
        return True

    return False


async def cleanup_expired_links(db: AsyncSession) -> int:
    """Clean up expired registration links"""
    result = await db.execute(
        delete(RegistrationLink).where(
            RegistrationLink.expires_at < datetime.now(timezone.utc)
        )
    )
    await db.commit()
    return result.rowcount


async def get_link_statistics(db: AsyncSession) -> dict:
    """Get registration link statistics"""
    from sqlalchemy import func

    # Total links
    total_result = await db.execute(select(func.count(RegistrationLink.id)))
    total_links = total_result.scalar()

    # Active links
    active_result = await db.execute(
        select(func.count(RegistrationLink.id)).where(
            RegistrationLink.is_active == True,
            RegistrationLink.expires_at > datetime.now(timezone.utc),
        )
    )
    active_links = active_result.scalar()

    # Expired links
    expired_result = await db.execute(
        select(func.count(RegistrationLink.id)).where(
            RegistrationLink.expires_at < datetime.now(timezone.utc)
        )
    )
    expired_links = expired_result.scalar()

    # Total device registrations
    total_devices_result = await db.execute(select(func.count(DeviceRegistration.id)))
    total_devices = total_devices_result.scalar()

    # Banned devices
    banned_devices_result = await db.execute(
        select(func.count(DeviceRegistration.id)).where(
            DeviceRegistration.is_banned == True
        )
    )
    banned_devices = banned_devices_result.scalar()

    return {
        "total_links": total_links,
        "active_links": active_links,
        "expired_links": expired_links,
        "total_devices": total_devices,
        "banned_devices": banned_devices,
    }


logger = logging.getLogger(__name__)

# Check if device fingerprinting should be enforced
ENFORCE_DEVICE_FINGERPRINT = (
    os.getenv("ENFORCE_DEVICE_FINGERPRINT", "false").lower() == "true"
)


async def optional_device_operation(
    db: AsyncSession,
    device_fingerprint: str,
    device_info: dict,
    electorate_id: uuid.UUID,
) -> Optional[DeviceRegistration]:
    """
    CENTRALIZED device registration handler
    Safely handles UNIQUE constraints and enforcement settings

    Returns:
        - DeviceRegistration if successful and enforcement enabled
        - None if enforcement disabled or operation failed (non-fatal)
    """

    # Skip if enforcement is disabled
    if not ENFORCE_DEVICE_FINGERPRINT:
        logger.debug(f"Device fingerprinting disabled for electorate {electorate_id}")
        return None

    try:
        # Check for existing device
        result = await db.execute(
            select(DeviceRegistration).where(
                DeviceRegistration.electorate_id == electorate_id,
                DeviceRegistration.device_fingerprint == device_fingerprint,
            )
        )
        device = result.scalar_one_or_none()

        if device:
            # Update existing device
            device.device_info = device_info
            device.last_attempt_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(device)
            return device

        # Create new device
        device = await create_device_registration_simple(
            db=db,
            device_fingerprint=device_fingerprint,
            device_info=device_info,
            electorate_id=electorate_id,
        )
        return device

    except IntegrityError as e:
        # UNIQUE constraint violation - handle gracefully
        await db.rollback()
        logger.warning(f"Device conflict for electorate {electorate_id}: {str(e)}")
        return None

    except Exception as e:
        # Any other error - don't break the flow
        await db.rollback()
        logger.error(f"Device registration error: {str(e)}")
        return None
