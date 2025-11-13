"""
Token Generation Service for On-Site Voting - FIXED

Fixed the token creation to properly work with CRUD functions.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from uuid import UUID
import logging
import hashlib

from fastapi import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.electorates import Electorate, Vote, VotingToken
from app.utils.security import FriendlyTokenGenerator
from app.services.notification_service import NotificationService

logger = logging.getLogger(__name__)


class BulkTokenGenerator:
    """Service for generating and distributing voting tokens in bulk"""

    def __init__(self):
        self.notification_service = NotificationService()
        self.token_generator = FriendlyTokenGenerator()

    async def generate_tokens_for_electorates(
        self,
        db: AsyncSession,
        electorate_ids: List[UUID],
        portfolio_id: Optional[UUID] = None,
        background_tasks: BackgroundTasks = None,
        election_name: str = "Election",
        voting_url: str = "http://localhost:8000",
        send_notifications: bool = True,
        notification_methods: List[str] = ["email", "sms"],
    ) -> Dict[str, Any]:
        """
        Generate voting tokens for a list of electorates
        """
        try:
            # Get electorates with their details
            electorates = await self._get_electorates_with_details(db, electorate_ids)

            if not electorates:
                return {
                    "success": False,
                    "message": "No electorates found",
                    "generated_tokens": 0,
                    "notifications_sent": 0,
                }

            # Generate tokens
            token_results = []
            voting_tokens = []

            for electorate in electorates:
                # Generate friendly token
                friendly_token = self.token_generator.generate_alphanumeric_code(
                    length=8
                )

                # Normalize and hash token
                clean_token = friendly_token.replace("-", "").replace(" ", "").upper()
                token_hash = hashlib.sha256(clean_token.encode()).hexdigest()

                # Create voting token record directly
                expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

                voting_token_record = VotingToken(
                    electorate_id=electorate.id,
                    token_hash=token_hash,
                    device_fingerprint="bulk_generated",
                    device_info={
                        "generated_by": "bulk_service",
                        "bulk_generation": True,
                    },
                    location_data=None,
                    ip_address="0.0.0.0",  # Bulk generated
                    user_agent="BulkTokenGenerator/1.0",
                    biometric_data_hash=None,
                    device_password_hash=None,
                    expires_at=expires_at,
                    is_active=True,
                )

                db.add(voting_token_record)

                token_results.append(
                    {
                        "electorate_id": str(electorate.id),
                        "student_id": electorate.student_id,
                        "name": f"Student {electorate.student_id}",
                        "token": friendly_token,  # Return formatted token
                        "expires_at": expires_at.isoformat(),
                        "created": True,
                    }
                )

                voting_tokens.append(friendly_token)

            # Commit all tokens at once
            await db.commit()

            # Send notifications if requested
            if send_notifications and background_tasks:
                voters_data = [
                    {
                        "id": str(electorate.id),
                        "name": f"Student {electorate.student_id}",
                        "email": electorate.email,
                        "phone": electorate.phone_number,
                    }
                    for electorate in electorates
                ]

                background_tasks.add_task(
                    self.notification_service.send_bulk_tokens,
                    voters_data,
                    voting_tokens,
                    voting_url,
                    election_name,
                    notification_methods,
                )

            return {
                "success": True,
                "message": f"Generated {len(token_results)} voting tokens",
                "generated_tokens": len(token_results),
                "tokens": token_results,
                "notifications_queued": send_notifications
                and background_tasks is not None,
            }

        except Exception as e:
            logger.error(f"Bulk token generation failed: {str(e)}")
            await db.rollback()
            return {
                "success": False,
                "message": f"Token generation failed: {str(e)}",
                "generated_tokens": 0,
                "notifications_sent": 0,
            }

    async def generate_tokens_for_all_electorates(
        self,
        db: AsyncSession,
        election_name: str = "Election",
        background_tasks: BackgroundTasks = None,
        voting_url: str = "http://localhost:8000",
        send_notifications: bool = True,
        notification_methods: List[str] = ["email", "sms"],
        exclude_voted: bool = True,
    ) -> Dict[str, Any]:
        """Generate voting tokens for all electorates"""
        try:
            # Get all electorates
            query = select(Electorate).where(Electorate.is_deleted == False)

            if exclude_voted:
                query = query.where(Electorate.has_voted == False)

            result = await db.execute(query)
            electorates = result.scalars().all()

            electorate_ids = [electorate.id for electorate in electorates]

            return await self.generate_tokens_for_electorates(
                db,
                electorate_ids,
                None,  # portfolio_id
                background_tasks,
                election_name,
                voting_url,
                send_notifications,
                notification_methods,
            )

        except Exception as e:
            logger.error(f"Bulk token generation for all electorates failed: {str(e)}")
            return {
                "success": False,
                "message": f"Token generation failed: {str(e)}",
                "generated_tokens": 0,
                "notifications_sent": 0,
            }

    async def generate_tokens_for_portfolio(
        self,
        db: AsyncSession,
        portfolio_id: UUID,
        background_tasks: BackgroundTasks = None,
        election_name: str = "Election",
        voting_url: str = "http://localhost:8000",
        send_notifications: bool = True,
        notification_methods: List[str] = ["email", "sms"],
    ) -> Dict[str, Any]:
        """Generate voting tokens for electorates who haven't voted for a specific portfolio"""
        try:
            # Get electorates who haven't voted for this portfolio
            # Subquery to get electorates who have already voted for this portfolio
            voted_subquery = (
                select(Vote.electorate_id)
                .where(Vote.portfolio_id == portfolio_id, Vote.is_valid == True)
                .scalar_subquery()
            )

            # Get electorates who haven't voted for this portfolio
            query = select(Electorate).where(
                Electorate.is_deleted == False, Electorate.id.not_in(voted_subquery)
            )

            result = await db.execute(query)
            electorates = result.scalars().all()

            electorate_ids = [electorate.id for electorate in electorates]

            return await self.generate_tokens_for_electorates(
                db,
                electorate_ids,
                portfolio_id,
                background_tasks,
                election_name,
                voting_url,
                send_notifications,
                notification_methods,
            )

        except Exception as e:
            logger.error(f"Bulk token generation for portfolio failed: {str(e)}")
            return {
                "success": False,
                "message": f"Token generation failed: {str(e)}",
                "generated_tokens": 0,
                "notifications_sent": 0,
            }

    async def _get_electorates_with_details(
        self, db: AsyncSession, electorate_ids: List[UUID]
    ) -> List[Electorate]:
        """Get electorates with their details"""
        result = await db.execute(
            select(Electorate)
            .where(Electorate.id.in_(electorate_ids))
            .where(Electorate.is_deleted == False)
        )
        return result.scalars().all()

    async def regenerate_token_for_electorate(
        self,
        db: AsyncSession,
        electorate_id: UUID,
        election_name: str = "Election",
        voting_url: str = "http://localhost:8000",
        send_notification: bool = True,
        notification_methods: List[str] = ["email", "sms"],
    ) -> Dict[str, Any]:
        """Regenerate a voting token for a specific electorate"""
        try:
            # Get electorate
            result = await db.execute(
                select(Electorate).where(Electorate.id == electorate_id)
            )
            electorate = result.scalar_one_or_none()

            if not electorate:
                return {
                    "success": False,
                    "message": "Electorate not found",
                    "token": None,
                }

            # Revoke old tokens for this electorate
            old_tokens_result = await db.execute(
                select(VotingToken).where(
                    VotingToken.electorate_id == electorate_id,
                    VotingToken.revoked == False,
                )
            )
            old_tokens = old_tokens_result.scalars().all()

            for old_token in old_tokens:
                old_token.revoked = True
                old_token.revoked_at = datetime.now(timezone.utc)
                old_token.revoked_reason = "Token regenerated"

            # Generate new token
            friendly_token = self.token_generator.generate_alphanumeric_code(length=8)
            clean_token = friendly_token.replace("-", "").replace(" ", "").upper()
            token_hash = hashlib.sha256(clean_token.encode()).hexdigest()

            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

            # Create voting token record
            voting_token_record = VotingToken(
                electorate_id=electorate.id,
                token_hash=token_hash,
                device_fingerprint="regenerated",
                device_info={"generated_by": "regeneration_service"},
                location_data=None,
                ip_address="0.0.0.0",
                user_agent="TokenRegenerator/1.0",
                biometric_data_hash=None,
                device_password_hash=None,
                expires_at=expires_at,
                is_active=True,
            )

            db.add(voting_token_record)

            # Send notification if requested
            notification_result = None
            if send_notification:
                voter_data = {
                    "id": str(electorate.id),
                    "name": f"Student {electorate.student_id}",
                    "email": f"{electorate.student_id}@student.edu",
                    "phone": f"+1234567890",
                }

                notification_result = await self.notification_service.send_voting_token(
                    voter_data,
                    friendly_token,
                    voting_url,
                    election_name,
                    notification_methods,
                )

            await db.commit()

            return {
                "success": True,
                "message": "Token regenerated successfully",
                "token": friendly_token,
                "expires_at": expires_at.isoformat(),
                "notification_sent": notification_result is not None,
                "notification_result": notification_result,
            }

        except Exception as e:
            logger.error(f"Token regeneration failed: {str(e)}")
            await db.rollback()
            return {
                "success": False,
                "message": f"Token regeneration failed: {str(e)}",
                "token": None,
            }

    async def get_token_statistics(self, db: AsyncSession) -> Dict[str, Any]:
        """Get statistics about generated tokens"""
        try:
            from sqlalchemy import func, distinct

            # Get total electorates
            total_electorates_result = await db.execute(
                select(func.count(Electorate.id)).where(Electorate.is_deleted == False)
            )
            total_electorates = total_electorates_result.scalar()

            # Get electorates with active tokens
            electorates_with_tokens_result = await db.execute(
                select(func.count(distinct(VotingToken.electorate_id))).where(
                    VotingToken.revoked == False,
                    VotingToken.expires_at > datetime.now(timezone.utc),
                )
            )
            electorates_with_tokens = electorates_with_tokens_result.scalar()

            # Get electorates who have voted
            voted_electorates_result = await db.execute(
                select(func.count(Electorate.id)).where(
                    Electorate.is_deleted == False, Electorate.has_voted == True
                )
            )
            voted_electorates = voted_electorates_result.scalar()

            return {
                "total_electorates": total_electorates,
                "electorates_with_tokens": electorates_with_tokens,
                "voted_electorates": voted_electorates,
                "pending_electorates": total_electorates - voted_electorates,
                "token_coverage": (
                    (electorates_with_tokens / total_electorates * 100)
                    if total_electorates > 0
                    else 0
                ),
                "voting_percentage": (
                    (voted_electorates / total_electorates * 100)
                    if total_electorates > 0
                    else 0
                ),
            }

        except Exception as e:
            logger.error(f"Failed to get token statistics: {str(e)}")
            return {"error": str(e)}
