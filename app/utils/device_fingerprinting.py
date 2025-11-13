"""
Device Fingerprinting and Security Utilities

This module provides comprehensive device fingerprinting capabilities for secure authentication,
including device identification, location verification, and biometric data handling.
"""

import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from fastapi import Request
from argon2 import PasswordHasher
import secrets


# Initialize password hasher
ph = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16
)


class DeviceFingerprinter:
    """Enhanced device fingerprinting with security features"""
    
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
    def parse_user_agent(user_agent: str) -> Dict[str, Any]:
        """Parse user agent for device information"""
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
            "bot", "crawler", "spider", "scraper", "curl", "wget",
            "python", "java", "axios", "node", "phantom", "selenium",
            "headless", "automated", "monitor", "test",
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
    def calculate_device_risk_score(device_data: Dict[str, Any]) -> Tuple[int, list]:
        """Calculate risk score based on device characteristics"""
        risk_score = 0
        risk_factors = []

        # Missing or suspicious user agent
        if not device_data.get("user_agent") or device_data.get("parsed_ua", {}).get("is_bot"):
            risk_score += 40
            risk_factors.append("suspicious_user_agent")

        # Missing standard browser headers
        if not device_data.get("accept_language"):
            risk_score += 90
            risk_factors.append("missing_accept_language")

        if not device_data.get("accept_encoding"):
            risk_score += 90
            risk_factors.append("missing_accept_encoding")

        # Check for automation tools in user agent
        user_agent = device_data.get("user_agent", "").lower()
        automation_indicators = [
            "selenium", "webdriver", "phantom", "headless", "automated",
        ]
        if any(indicator in user_agent for indicator in automation_indicators):
            risk_score += 100
            risk_factors.append("automation_detected")

        # Suspicious IP patterns
        client_ip = device_data.get("client_ip", "")
        if client_ip in ["unknown", "127.0.0.1", "localhost"] or not client_ip:
            risk_score += 100
            risk_factors.append("suspicious_ip")

        # Check for common VPN/proxy patterns
        vpn_indicators = ["vpn", "proxy", "tor"]
        headers_str = " ".join([
            device_data.get("user_agent", ""),
            device_data.get("accept_language", ""),
            device_data.get("accept_encoding", ""),
        ]).lower()

        if any(indicator in headers_str for indicator in vpn_indicators):
            risk_score += 100
            risk_factors.append("proxy_detected")

        return min(risk_score, 100), risk_factors


    @staticmethod
    def extract_device_info(request: Request) -> Dict[str, Any]:
        """
        Extract comprehensive device fingerprinting information for robust authentication
        """
        # Extract basic headers
        user_agent = request.headers.get("user-agent", "").strip()
        accept_language = request.headers.get("accept-language", "").strip()
        accept_encoding = request.headers.get("accept-encoding", "").strip()

        # Get client IP with enhanced proxy support
        client_ip = DeviceFingerprinter.extract_client_ip(request)

        # Parse user agent for additional insights
        parsed_ua = DeviceFingerprinter.parse_user_agent(user_agent)

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
    
        # Normalize accept-encoding by sorting and removing quality values
        normalized_encoding = ""
        if accept_encoding:
            # Split by comma, remove quality values, sort, and rejoin
            encodings = [enc.split(";")[0].strip().lower() for enc in accept_encoding.split(",")]
            normalized_encoding = ",".join(sorted(set(filter(None, encodings))))

        # ===== STABLE FINGERPRINT =====
        # Use ONLY the most stable components that rarely change on the same device
        stable_components = [
            parsed_ua.get("browser", ""),
            parsed_ua.get("os", ""),
            parsed_ua.get("device_type", ""),  # mobile/desktop/tablet
            normalized_language.split("-")[0] if normalized_language else "",  # Just language code (e.g., 'en')
            # DO NOT include IP unless it's a public IP
            (
                client_ip
                if client_ip and not client_ip.startswith(("127.", "192.168.", "10.", "172.", "unknown"))
                else ""
            ),
        ]

        fingerprint_data = "|".join(filter(None, stable_components))
        fingerprint = hashlib.sha256(fingerprint_data.encode("utf-8")).hexdigest()[:32]

        # Security fingerprint (includes more headers for fraud detection, but not used for matching)
        security_components = stable_components + [
            normalized_encoding,
            security_headers.get("sec_ch_ua", ""),
            security_headers.get("sec_ch_ua_platform", ""),
        ]

        security_fingerprint_data = "|".join(filter(None, security_components))
        security_fingerprint = hashlib.sha256(
            security_fingerprint_data.encode("utf-8")
        ).hexdigest()[:32]

        # Compile device information
        device_data = {
            "user_agent": user_agent,
            "accept_language": accept_language,
            "accept_encoding": accept_encoding,
            "client_ip": client_ip,
            "fingerprint": fingerprint,  # ← More stable now
            "security_fingerprint": security_fingerprint,
            "parsed_ua": parsed_ua,
            "normalized_language": normalized_language,
            "normalized_encoding": normalized_encoding,
            "security_headers": security_headers,
            "timestamp": datetime.now(timezone.utc).timestamp(),
            "fingerprint_components": stable_components,  # For debugging
            "has_security_headers": bool(any(security_headers.values())),
        }

        # Calculate risk assessment
        risk_score, risk_factors = DeviceFingerprinter.calculate_device_risk_score(device_data)
        device_data.update({
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "risk_level": (
                "high" if risk_score >= 70
                else "medium" if risk_score >= 30 else "low"
            ),
        })

        return device_data


class LocationVerifier:
    """Location verification utilities"""
    
    @staticmethod
    def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two coordinates using Haversine formula"""
        import math
        
        # Convert latitude and longitude from degrees to radians
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        # Radius of earth in kilometers
        r = 6371
        return c * r

    @staticmethod
    def verify_location(
        stored_location: Dict[str, Any], 
        current_location: Dict[str, Any], 
        max_distance_km: float = 10.0
    ) -> Tuple[bool, str]:
        """
        Verify if current location matches stored location within acceptable distance
        
        Args:
            stored_location: Previously stored location data
            current_location: Current location data
            max_distance_km: Maximum allowed distance in kilometers
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if not stored_location or not current_location:
            return False, "Location data missing"
        
        try:
            stored_lat = stored_location.get("latitude")
            stored_lon = stored_location.get("longitude")
            current_lat = current_location.get("latitude")
            current_lon = current_location.get("longitude")
            
            if not all([stored_lat, stored_lon, current_lat, current_lon]):
                return False, "Invalid location coordinates"
            
            distance = LocationVerifier.calculate_distance(
                stored_lat, stored_lon, current_lat, current_lon
            )
            
            if distance <= max_distance_km:
                return True, f"Location verified (distance: {distance:.2f}km)"
            else:
                return False, f"Location mismatch (distance: {distance:.2f}km)"
                
        except Exception as e:
            return False, f"Location verification error: {str(e)}"


class BiometricManager:
    """Biometric data management utilities"""
    
    @staticmethod
    def hash_biometric_data(biometric_data: str) -> str:
        """Hash biometric data for secure storage"""
        if not biometric_data:
            return ""
        
        # Add salt for additional security
        salt = secrets.token_hex(16)
        combined = f"{biometric_data}:{salt}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @staticmethod
    def verify_biometric_data(stored_hash: str, provided_data: str) -> bool:
        """Verify biometric data against stored hash"""
        if not stored_hash or not provided_data:
            return False
        
        # This is a simplified verification - in production, you'd need
        # more sophisticated biometric matching algorithms
        current_hash = BiometricManager.hash_biometric_data(provided_data)
        return stored_hash == current_hash


class DevicePasswordManager:
    """Device password management utilities"""
    
    @staticmethod
    def hash_device_password(password: str) -> str:
        """Hash device password using Argon2"""
        if not password:
            return ""
        return ph.hash(password)
    
    @staticmethod
    def verify_device_password(stored_hash: str, provided_password: str) -> bool:
        """Verify device password against stored hash"""
        if not stored_hash or not provided_password:
            return False
        
        try:
            ph.verify(stored_hash, provided_password)
            return True
        except Exception:
            return False


class SecurityValidator:
    """Comprehensive security validation utilities"""

    @staticmethod
    def validate_device_registration(
        device_fingerprint: str,
        ip_address: str,
        device_info: Dict[str, Any],
        max_devices_per_link: int = 1
    ) -> Tuple[bool, str]:
        """
        Validate device registration attempt
        
        Returns:
            Tuple of (is_valid, reason)
        """
        # Check risk score
        risk_score = device_info.get("risk_score", 0)
        if risk_score >= 70:
            return False, "High risk device detected"

        # Check for bot indicators
        parsed_ua = device_info.get("parsed_ua", {})
        if parsed_ua.get("is_bot", False):
            return False, "Bot detected"

        # Check IP address validity
        # if ip_address in ["unknown", "127.0.0.1", "localhost"]:
        #     return False, "Invalid IP address"

        return True, "Device validation passed"

    @staticmethod
    def validate_token_usage(
        token_data: Dict[str, Any],
        current_device_fingerprint: str,
        current_location: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, Dict[str, bool]]:
        """
        Validate token usage for voting
        
        Returns:
            Tuple of (is_valid, reason, flags)
        """
        flags = {
            "device_mismatch": False,
            "location_mismatch": False,
            "token_expired": False,
            "token_revoked": False,
        }

        # Check token expiration
        expires_at = token_data.get("expires_at")
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        if expires_at and datetime.now(timezone.utc) > expires_at:
            flags["token_expired"] = True
            return False, "Token has expired", flags

        # Check if token is revoked
        if token_data.get("revoked", False):
            flags["token_revoked"] = True
            return False, "Token has been revoked", flags

        # Check device fingerprint match
        stored_fingerprint = token_data.get("device_fingerprint")
        if stored_fingerprint != current_device_fingerprint:
            flags["device_mismatch"] = True
            return False, "Device fingerprint mismatch", flags

        # Check location if provided
        if current_location:
            stored_location = token_data.get("location_data")
            if stored_location:
                is_valid, reason = LocationVerifier.verify_location(
                    stored_location, current_location
                )
                if not is_valid:
                    flags["location_mismatch"] = True
                    return False, f"Location verification failed: {reason}", flags

        return True, "Token validation passed", flags


def get_device_fingerprint(request: Request) -> str:
    """Get device fingerprint from request - compatibility function"""
    device_info = DeviceFingerprinter.extract_device_info(request)
    return device_info.get("fingerprint", "")


def verify_pin(voting_pin: str, stored_hash: str) -> bool:
    """Verify voting PIN against stored hash - compatibility function"""
    try:
        ph.verify(stored_hash, voting_pin)
        return True
    except Exception:
        return False
