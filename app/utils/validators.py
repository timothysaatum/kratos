import math
from typing import Optional

from fastapi import Request


def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two coordinates in kilometers using Haversine formula"""
    R = 6371  # Earth's radius in kilometers

    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = math.sin(dlat / 2) * math.sin(dlat / 2) + math.cos(
        math.radians(lat1)
    ) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) * math.sin(dlon / 2)

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def validate_geolocation(
    current_location: Optional[dict],
    stored_location: Optional[dict],
    max_distance_km: float = 50.0,
) -> tuple[bool, str]:
    """
    Validate geolocation consistency between current and stored locations

    Args:
        current_location: Current location from request
        stored_location: Stored location from token
        max_distance_km: Maximum allowed distance in kilometers

    Returns:
        Tuple of (is_valid, reason)
    """
    if not current_location or not stored_location:
        return True, "No location data to validate"

    try:
        current_lat = current_location.get("latitude")
        current_lon = current_location.get("longitude")
        stored_lat = stored_location.get("latitude")
        stored_lon = stored_location.get("longitude")

        if not all([current_lat, current_lon, stored_lat, stored_lon]):
            return True, "Incomplete location data"

        distance = calculate_distance(
            float(current_lat), float(current_lon), float(stored_lat), float(stored_lon)
        )

        if distance > max_distance_km:
            return (
                False,
                f"Location mismatch: {distance:.2f}km from registration location",
            )

        return True, "Location validated"

    except (ValueError, TypeError) as e:
        return False, f"Invalid location data: {str(e)}"


def validate_request_headers(request: Request) -> tuple[bool, str]:
    """
    Validate security headers and request characteristics

    Returns:
        Tuple of (is_valid, reason)
    """
    # Check for required security headers
    required_headers = ["user-agent", "accept-language"]
    missing_headers = [h for h in required_headers if not request.headers.get(h)]

    if missing_headers:
        return False, f"Missing required headers: {', '.join(missing_headers)}"

    # Check for suspicious headers
    suspicious_headers = ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]
    proxy_headers = [h for h in suspicious_headers if request.headers.get(h)]

    if len(proxy_headers) > 1:
        return False, "Multiple proxy headers detected"

    # Check for bot-like behavior
    user_agent = request.headers.get("user-agent", "").lower()
    bot_indicators = ["bot", "crawler", "spider", "scraper", "curl", "wget"]

    if any(indicator in user_agent for indicator in bot_indicators):
        return False, "Bot-like user agent detected"

    return True, "Headers validated"


def generate_csrf_token() -> str:
    """Generate a CSRF token for form protection"""
    import secrets

    return secrets.token_urlsafe(32)
