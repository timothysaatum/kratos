from datetime import datetime
import json


class SecurityAuditLogger:
    """Enhanced security audit logging for voting system"""

    @staticmethod
    def log_security_event(
        event_type: str,
        user_id: str = None,
        ip_address: str = None,
        device_fingerprint: str = None,
        details: dict = None,
        severity: str = "INFO",
    ):
        """Log security events with structured data"""
        import logging
        import json
        from datetime import datetime, timezone

        logger = logging.getLogger("security_audit")

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "device_fingerprint": (
                device_fingerprint[:8] + "..." if device_fingerprint else None
            ),
            "details": details or {},
            "severity": severity,
        }

        if severity == "ERROR":
            logger.error(json.dumps(log_entry))
        elif severity == "WARNING":
            logger.warning(json.dumps(log_entry))
        else:
            logger.info(json.dumps(log_entry))

    @staticmethod
    def log_voting_attempt(
        electorate_id: str,
        ip_address: str,
        device_fingerprint: str,
        success: bool,
        reason: str = None,
    ):
        """Log voting attempt"""
        SecurityAuditLogger.log_security_event(
            event_type="voting_attempt",
            user_id=electorate_id,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            details={"success": success, "reason": reason},
            severity="WARNING" if not success else "INFO",
        )

    @staticmethod
    def log_session_creation(
        electorate_id: str,
        ip_address: str,
        device_fingerprint: str,
        session_duration: int,
    ):
        """Log session creation"""
        SecurityAuditLogger.log_security_event(
            event_type="session_created",
            user_id=electorate_id,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            details={"session_duration_minutes": session_duration},
            severity="INFO",
        )

    @staticmethod
    def log_security_violation(
        violation_type: str, ip_address: str, device_fingerprint: str, details: dict
    ):
        """Log security violations"""
        SecurityAuditLogger.log_security_event(
            event_type="security_violation",
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            details={"violation_type": violation_type, **details},
            severity="ERROR",
        )
