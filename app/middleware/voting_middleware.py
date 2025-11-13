"""
Voting Middleware for Enhanced Security

This middleware provides additional security checks for voting operations
including vote validation, duplicate prevention, and audit logging.
"""

from fastapi import Request, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any
from datetime import datetime, timezone
import logging

from app.models.electorates import Vote, Electorate, Portfolio, Candidate
from sqlalchemy.orm import selectinload
from app.crud.crud_votes import check_electorate_voted_for_portfolio, get_vote_count_by_candidate
from app.crud.crud_portfolios import get_portfolio
from app.crud.crud_candidates import get_candidate
from app.utils.device_fingerprinting import DeviceFingerprinter

logger = logging.getLogger(__name__)


class VotingSecurityValidator:
    """Enhanced security validation for voting operations"""
    
    @staticmethod
    async def validate_vote_request(
        db: AsyncSession,
        electorate_id: str,
        portfolio_id: str,
        candidate_id: str,
        request: Request
    ) -> Dict[str, Any]:
        """
        Comprehensive vote validation
        
        Args:
            db: Database session
            electorate_id: ID of the electorate
            portfolio_id: ID of the portfolio
            candidate_id: ID of the candidate
            request: FastAPI request object
            
        Returns:
            Dictionary containing validation results
            
        Raises:
            HTTPException: If validation fails
        """
        try:
            # 1. Check if electorate has already voted for this portfolio
            has_voted = await check_electorate_voted_for_portfolio(
                db, electorate_id, portfolio_id
            )
            if has_voted:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You have already voted for this portfolio"
                )
            
            # 2. Verify portfolio exists and is active
            portfolio = await get_portfolio(db, portfolio_id)
            if not portfolio:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Portfolio not found"
                )
            
            if not portfolio.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Portfolio is not active for voting"
                )
            
            # 3. Verify candidate exists and belongs to portfolio
            candidate = await get_candidate(db, candidate_id)
            if not candidate:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Candidate not found"
                )
            
            if candidate.portfolio_id != portfolio_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Candidate does not belong to this portfolio"
                )
            
            if not candidate.is_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Candidate is not active"
                )
            
            # 4. Check for suspicious voting patterns
            device_info = DeviceFingerprinter.extract_device_info(request)
            client_ip = device_info.get("client_ip")
            
            # Check for rapid voting from same IP
            recent_votes_count = await VotingSecurityValidator._check_rapid_voting(
                db, client_ip, electorate_id
            )
            
            if recent_votes_count > 5:  # More than 5 votes in 1 hour
                logger.warning(f"Suspicious rapid voting detected: IP {client_ip}, Electorate {electorate_id}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many votes in a short time. Please slow down."
                )
            
            # 5. Validate voting session
            session_valid = await VotingSecurityValidator._validate_voting_session(
                request, electorate_id
            )
            
            if not session_valid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired voting session"
                )
            
            return {
                "valid": True,
                "portfolio": portfolio,
                "candidate": candidate,
                "device_info": device_info
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Vote validation error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Vote validation failed"
            )
    
    @staticmethod
    async def _check_rapid_voting(
        db: AsyncSession, 
        client_ip: str, 
        electorate_id: str
    ) -> int:
        """Check for rapid voting patterns"""
        from sqlalchemy.future import select
        from datetime import timedelta
        
        # Check votes in the last hour
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        
        result = await db.execute(
            select(Vote.id)
            .where(
                Vote.electorate_id == electorate_id,
                Vote.ip_address == client_ip,
                Vote.voted_at >= one_hour_ago,
                Vote.is_valid == True
            )
        )
        
        return len(result.scalars().all())
    
    @staticmethod
    async def _validate_voting_session(request: Request, electorate_id: str) -> bool:
        """Validate that the request comes from a valid voting session"""
        try:
            # Get session token from cookie
            session_token = request.cookies.get("voting_session")
            if not session_token:
                return False
            
            # This would typically check against the database
            # For now, we'll assume the session is valid if the token exists
            # In a real implementation, you'd verify the session in the database
            return True
            
        except Exception:
            return False
    
    @staticmethod
    async def log_vote_attempt(
        electorate_id: str,
        portfolio_id: str,
        candidate_id: str,
        success: bool,
        reason: str = None,
        device_info: Dict[str, Any] = None
    ):
        """Log vote attempt for audit purposes"""
        try:
            log_data = {
                "electorate_id": electorate_id,
                "portfolio_id": portfolio_id,
                "candidate_id": candidate_id,
                "success": success,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_address": device_info.get("client_ip") if device_info else None,
                "device_fingerprint": device_info.get("fingerprint") if device_info else None
            }
            
            if success:
                logger.info(f"Vote cast successfully: {log_data}")
            else:
                logger.warning(f"Vote attempt failed: {log_data}")
                
        except Exception as e:
            logger.error(f"Failed to log vote attempt: {str(e)}")


class VoteIntegrityChecker:
    """Check vote integrity and detect anomalies"""
    
    @staticmethod
    async def check_vote_integrity(
        db: AsyncSession,
        vote_id: str
    ) -> Dict[str, Any]:
        """
        Check the integrity of a specific vote
        
        Returns:
            Dictionary with integrity check results
        """
        try:
            from sqlalchemy.future import select
            
            # Get vote details
            result = await db.execute(
                select(Vote)
                .options(
                    selectinload(Vote.electorate),
                    selectinload(Vote.portfolio),
                    selectinload(Vote.candidate)
                )
                .where(Vote.id == vote_id)
            )
            vote = result.scalar_one_or_none()
            
            if not vote:
                return {"valid": False, "reason": "Vote not found"}
            
            integrity_checks = {
                "vote_exists": True,
                "electorate_valid": vote.electorate is not None,
                "portfolio_valid": vote.portfolio is not None,
                "candidate_valid": vote.candidate is not None,
                "session_valid": vote.voting_session_id is not None,
                "timestamp_valid": vote.voted_at is not None,
                "is_valid": vote.is_valid
            }
            
            # Check for duplicate votes
            duplicate_check = await db.execute(
                select(Vote.id)
                .where(
                    Vote.electorate_id == vote.electorate_id,
                    Vote.portfolio_id == vote.portfolio_id,
                    Vote.id != vote.id,
                    Vote.is_valid == True
                )
            )
            integrity_checks["no_duplicates"] = len(duplicate_check.scalars().all()) == 0
            
            # Overall integrity
            integrity_checks["overall_valid"] = all(integrity_checks.values())
            
            return integrity_checks
            
        except Exception as e:
            logger.error(f"Vote integrity check failed: {str(e)}")
            return {"valid": False, "reason": f"Check failed: {str(e)}"}
    
    @staticmethod
    async def detect_anomalies(
        db: AsyncSession,
        portfolio_id: str
    ) -> Dict[str, Any]:
        """
        Detect voting anomalies for a portfolio
        
        Returns:
            Dictionary with anomaly detection results
        """
        try:
            from sqlalchemy.future import select
            from sqlalchemy import func
            
            # Get vote statistics
            stats_result = await db.execute(
                select(
                    func.count(Vote.id).label('total_votes'),
                    func.count(func.distinct(Vote.electorate_id)).label('unique_voters'),
                    func.count(func.distinct(Vote.ip_address)).label('unique_ips')
                )
                .where(
                    Vote.portfolio_id == portfolio_id,
                    Vote.is_valid == True
                )
            )
            stats = stats_result.first()
            
            # Calculate anomaly indicators
            votes_per_voter = stats.total_votes / stats.unique_voters if stats.unique_voters > 0 else 0
            votes_per_ip = stats.total_votes / stats.unique_ips if stats.unique_ips > 0 else 0
            
            anomalies = {
                "total_votes": stats.total_votes,
                "unique_voters": stats.unique_voters,
                "unique_ips": stats.unique_ips,
                "votes_per_voter": round(votes_per_voter, 2),
                "votes_per_ip": round(votes_per_ip, 2),
                "suspicious_voter_ratio": votes_per_voter > 1.1,  # More votes than voters
                "suspicious_ip_ratio": votes_per_ip > 10,  # Many votes from same IP
                "low_participation": stats.unique_voters < 5  # Very few voters
            }
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {str(e)}")
            return {"error": str(e)}


# Rate limiting for voting operations
class VotingRateLimiter:
    """Rate limiting specifically for voting operations"""
    
    def __init__(self):
        self.vote_attempts = {}  # In production, use Redis or similar
    
    def is_vote_rate_limited(self, electorate_id: str, time_window: int = 300) -> bool:
        """
        Check if electorate is rate limited for voting
        
        Args:
            electorate_id: ID of the electorate
            time_window: Time window in seconds (default 5 minutes)
            
        Returns:
            True if rate limited, False otherwise
        """
        import time
        
        now = time.time()
        key = f"vote_{electorate_id}"
        
        if key not in self.vote_attempts:
            self.vote_attempts[key] = []
        
        # Clean old attempts
        self.vote_attempts[key] = [
            attempt_time for attempt_time in self.vote_attempts[key]
            if now - attempt_time < time_window
        ]
        
        # Check rate limit (max 3 votes per 5 minutes)
        if len(self.vote_attempts[key]) >= 3:
            return True
        
        # Record this attempt
        self.vote_attempts[key].append(now)
        return False


# Global rate limiter instance
voting_rate_limiter = VotingRateLimiter()
