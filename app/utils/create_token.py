# Helper function to create voting token for a device
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from app.crud.crud_voting_tokens import create_voting_token
from app.models.electorates import DeviceRegistration
from app.schemas.electorates import LinkRegistrationRequest
from app.utils.security import TokenManager

async def create_voting_token_for_device(
        db: AsyncSession,
        device_registration: DeviceRegistration,
        device_info: dict,
        registration_data: LinkRegistrationRequest
    ) -> str:
    """Create a voting token for a registered device"""
    
    # Create JWT token with device and biometric information
    token_data = {
        "sub": str(device_registration.id),
        "device_fingerprint": device_registration.device_fingerprint,
        "full_name": device_registration.full_name,
        "ip_address": device_registration.ip_address,
        "registration_time": device_registration.created_at.isoformat(),
    }
    
    # Add biometric data hash if provided
    if device_registration.biometric_data_hash:
        token_data["biometric_hash"] = device_registration.biometric_data_hash
    
    # Add device password hash if provided
    if device_registration.device_password_hash:
        token_data["device_password_hash"] = device_registration.device_password_hash
    
    # Add location data if provided
    if device_registration.location_data:
        token_data["location"] = device_registration.location_data
    
    # Create friendly voting token (expires in 24 hours)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    friendly_token = TokenManager.create_voting_token(
        user_id=device_registration.id,
        device_info=device_registration.device_fingerprint,
        ip_address=device_registration.ip_address
    )
    
    # Store token in database
    from app.schemas.electorates import VotingTokenCreate, DeviceInfo
    
    device_info_schema = DeviceInfo(
        user_agent=device_info.get("user_agent", ""),
        browser=device_info.get("parsed_ua", {}).get("browser", "unknown"),
        os=device_info.get("parsed_ua", {}).get("os", "unknown"),
        device_type=device_info.get("parsed_ua", {}).get("device_type", "unknown"),
        fingerprint=device_info.get("fingerprint", ""),
        security_fingerprint=device_info.get("security_fingerprint", ""),
        risk_score=device_info.get("risk_score", 0),
        risk_level=device_info.get("risk_level", "low"),
        risk_factors=device_info.get("risk_factors", [])
    )
    
    token_create = VotingTokenCreate(
        electorate_id=device_registration.electorate_id or device_registration.id,
        device_fingerprint=device_registration.device_fingerprint,
        device_info=device_info_schema,
        location_data=registration_data.location,
        biometric_data=registration_data.biometric_data,
        device_password=registration_data.device_password
    )
    
    # Note: We need to associate with an electorate for voting
    # For now, we'll use the device registration ID as a placeholder
    voting_token_record = await create_voting_token(
        db, token_create, friendly_token, expires_at
    )
    
    return friendly_token
