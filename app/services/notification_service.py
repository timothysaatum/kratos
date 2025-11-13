"""
Notification Service for SMS and Email Distribution

This service handles sending voting tokens via SMS and email to voters.
Supports multiple providers and fallback mechanisms.
"""

import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class NotificationResult:
    """Result of a notification attempt"""

    success: bool
    message: str
    provider: str
    timestamp: datetime
    error: Optional[str] = None


class EmailService:
    """Email service for sending voting tokens"""

    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.from_email = os.getenv("FROM_EMAIL", "noreply@voting-system.com")
        self.from_name = os.getenv("FROM_NAME", "Election System")

        # Validate configuration
        if not self.smtp_username or not self.smtp_password:
            logger.warning(
                "SMTP credentials not configured. Email notifications will fail."
            )

    async def send_voting_token(
        self,
        to_email: str,
        voter_name: str,
        voting_token: str,
        voting_url: str,
        election_name: str = "Election",
    ) -> NotificationResult:
        """Send voting token via email"""
        try:
            # Validate credentials
            if not self.smtp_username or not self.smtp_password:
                raise Exception(
                    "SMTP credentials not configured in environment variables"
                )

            # Create message
            msg = MIMEMultipart("alternative")
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email
            msg["Subject"] = f"Your Voting Token - {election_name}"

            # Create HTML content
            html_content = self._create_email_template(
                voter_name, voting_token, voting_url, election_name
            )

            # Create plain text version
            text_content = f"""
{election_name} - Your Voting Token

Hello {voter_name}!

Your voting token has been generated. Please use this token to cast your vote.

Your Voting Token: {voting_token}

Vote at: {voting_url}

IMPORTANT:
- Keep this token secure and do not share it with anyone
- This token is valid for 15 minutes after first use
- You can only vote once per portfolio
- Vote from the same device you registered with

If you have any questions or issues, please contact the election administrators immediately.

---
This is an automated message. Please do not reply to this email.
© 2024 Election System. All rights reserved.
            """

            # Attach both plain text and HTML
            text_part = MIMEText(text_content, "plain")
            html_part = MIMEText(html_content, "html")
            msg.attach(text_part)
            msg.attach(html_part)

            # Create secure SSL context
            context = ssl.create_default_context()

            # Send email with proper error handling
            try:
                with smtplib.SMTP(
                    self.smtp_server, self.smtp_port, timeout=30
                ) as server:
                    server.set_debuglevel(0)  # Set to 1 for debugging

                    # Start TLS encryption
                    server.starttls(context=context)

                    # Login with credentials
                    server.login(self.smtp_username, self.smtp_password)

                    # Send the email
                    server.send_message(msg)

                logger.info(f"Email sent successfully to {to_email}")

                return NotificationResult(
                    success=True,
                    message=f"Email sent successfully to {to_email}",
                    provider="email",
                    timestamp=datetime.now(timezone.utc),
                )

            except smtplib.SMTPAuthenticationError as e:
                error_msg = f"SMTP Authentication failed: {str(e)}"
                logger.error(error_msg)
                logger.error("Please check:")
                logger.error("1. SMTP_USERNAME and SMTP_PASSWORD are correct in .env")
                logger.error("2. For Gmail: Use App Password (not regular password)")
                logger.error("3. For Gmail: Enable 2-Factor Authentication first")
                raise Exception(error_msg)

            except smtplib.SMTPException as e:
                error_msg = f"SMTP error: {str(e)}"
                logger.error(error_msg)
                raise Exception(error_msg)

        except Exception as e:
            error_msg = f"Email sending failed: {str(e)}"
            logger.error(error_msg)
            return NotificationResult(
                success=False,
                message=f"Failed to send email to {to_email}",
                provider="email",
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )

    def _create_email_template(
        self, voter_name: str, voting_token: str, voting_url: str, election_name: str
    ) -> str:
        """Create HTML email template"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Your Voting Token</title>
            <style>
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    line-height: 1.6; 
                    color: #333;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }}
                .container {{ 
                    max-width: 600px; 
                    margin: 20px auto; 
                    background-color: #ffffff;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }}
                .header {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    padding: 40px 20px; 
                    text-align: center; 
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 600;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    font-size: 16px;
                    opacity: 0.9;
                }}
                .content {{ 
                    padding: 40px 30px; 
                }}
                .content h2 {{
                    color: #333;
                    font-size: 20px;
                    margin-top: 0;
                }}
                .token-box {{ 
                    background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
                    border: 2px solid #667eea; 
                    padding: 25px; 
                    margin: 30px 0; 
                    text-align: center; 
                    border-radius: 8px; 
                }}
                .token-label {{
                    font-size: 14px;
                    color: #666;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-bottom: 10px;
                }}
                .token {{ 
                    font-size: 32px; 
                    font-weight: bold; 
                    color: #667eea; 
                    letter-spacing: 4px;
                    font-family: 'Courier New', monospace;
                    margin: 10px 0;
                }}
                .button {{ 
                    display: inline-block; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white !important; 
                    padding: 14px 32px; 
                    text-decoration: none; 
                    border-radius: 6px; 
                    margin: 20px 0;
                    font-weight: 600;
                    transition: transform 0.2s;
                }}
                .button:hover {{
                    transform: translateY(-2px);
                }}
                .footer {{ 
                    text-align: center; 
                    color: #999; 
                    font-size: 12px; 
                    padding: 20px;
                    background-color: #f9f9f9;
                    border-top: 1px solid #e5e5e5;
                }}
                .warning {{ 
                    background-color: #fff3cd; 
                    border-left: 4px solid #ffc107; 
                    padding: 15px; 
                    border-radius: 4px; 
                    margin: 20px 0; 
                }}
                .warning strong {{
                    color: #856404;
                    display: block;
                    margin-bottom: 8px;
                }}
                .warning ul {{
                    margin: 8px 0;
                    padding-left: 20px;
                }}
                .warning li {{
                    margin: 4px 0;
                    color: #856404;
                }}
                .info-box {{
                    background-color: #e7f3ff;
                    border-left: 4px solid #2196F3;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 20px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🗳️ {election_name}</h1>
                    <p>Your Voting Token is Ready</p>
                </div>
                
                <div class="content">
                    <h2>Hello {voter_name}!</h2>
                    
                    <p>Your voting token has been generated. Please use this token to cast your vote in the {election_name}.</p>
                    
                    <div class="token-box">
                        <div class="token-label">Your Voting Token</div>
                        <div class="token">{voting_token}</div>
                    </div>
                    
                    <div class="warning">
                        <strong>⚠️ Important Security Information:</strong>
                        <ul>
                            <li>Keep this token secure and do not share it with anyone</li>
                            <li>This token is valid for 15 minutes after first use</li>
                            <li>You can only vote once per portfolio</li>
                            <li>Vote from the same device you registered with</li>
                            <li>Report any suspicious activity immediately</li>
                        </ul>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="{voting_url}" class="button">Start Voting Now</a>
                    </div>
                    
                    <div class="info-box">
                        <strong>Voting URL:</strong><br>
                        <a href="{voting_url}" style="color: #2196F3; word-break: break-all;">{voting_url}</a>
                    </div>
                    
                    <p style="margin-top: 30px; color: #666;">If you have any questions or encounter any issues, please contact the election administrators immediately.</p>
                </div>
                
                <div class="footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>© 2024 {self.from_name}. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """


class SMSService:
    """SMS service for sending voting tokens"""

    def __init__(self):
        self.provider = os.getenv(
            "SMS_PROVIDER", "twilio"
        )  # twilio, africastalking, etc.
        self.api_key = os.getenv("SMS_API_KEY")
        self.api_secret = os.getenv("SMS_API_SECRET")
        self.from_number = os.getenv("SMS_FROM_NUMBER")

    async def send_voting_token(
        self,
        to_phone: str,
        voter_name: str,
        voting_token: str,
        voting_url: str,
        election_name: str = "Election",
    ) -> NotificationResult:
        """Send voting token via SMS"""
        try:
            if not self.api_key:
                logger.warning("SMS API not configured. Skipping SMS notification.")
                return NotificationResult(
                    success=False,
                    message="SMS service not configured",
                    provider="sms",
                    timestamp=datetime.now(timezone.utc),
                    error="SMS_API_KEY not set in environment",
                )

            if self.provider == "twilio":
                return await self._send_via_twilio(
                    to_phone, voter_name, voting_token, voting_url, election_name
                )
            elif self.provider == "africastalking":
                return await self._send_via_africastalking(
                    to_phone, voter_name, voting_token, voting_url, election_name
                )
            else:
                return await self._send_via_generic(
                    to_phone, voter_name, voting_token, voting_url, election_name
                )

        except Exception as e:
            logger.error(f"SMS sending failed: {str(e)}")
            return NotificationResult(
                success=False,
                message=f"Failed to send SMS to {to_phone}",
                provider="sms",
                timestamp=datetime.now(timezone.utc),
                error=str(e),
            )

    async def _send_via_twilio(
        self,
        to_phone: str,
        voter_name: str,
        voting_token: str,
        voting_url: str,
        election_name: str,
    ) -> NotificationResult:
        """Send SMS via Twilio"""
        try:
            from twilio.rest import Client

            client = Client(self.api_key, self.api_secret)

            message = f"""🗳️ {election_name}

Hello {voter_name}!

Your voting token: {voting_token}

Vote at: {voting_url}

⚠️ Keep this token secure. Valid for 15 minutes after first use.

Do not share this token with anyone."""

            message_obj = client.messages.create(
                body=message, from_=self.from_number, to=to_phone
            )

            return NotificationResult(
                success=True,
                message=f"SMS sent successfully to {to_phone}",
                provider="twilio",
                timestamp=datetime.now(timezone.utc),
            )

        except Exception as e:
            raise Exception(f"Twilio error: {str(e)}")

    async def _send_via_africastalking(
        self,
        to_phone: str,
        voter_name: str,
        voting_token: str,
        voting_url: str,
        election_name: str,
    ) -> NotificationResult:
        """Send SMS via Africa's Talking"""
        try:
            import africastalking

            africastalking.initialize(self.api_key, self.api_secret)
            sms = africastalking.SMS

            message = f"""🗳️ {election_name}

Hello {voter_name}!

Your voting token: {voting_token}

Vote at: {voting_url}

⚠️ Keep this token secure. Valid for 15 minutes after first use."""

            response = sms.send(message, [to_phone])

            return NotificationResult(
                success=True,
                message=f"SMS sent successfully to {to_phone}",
                provider="africastalking",
                timestamp=datetime.now(timezone.utc),
            )

        except Exception as e:
            raise Exception(f"Africa's Talking error: {str(e)}")

    async def _send_via_generic(
        self,
        to_phone: str,
        voter_name: str,
        voting_token: str,
        voting_url: str,
        election_name: str,
    ) -> NotificationResult:
        """Generic SMS sending (for testing or custom providers)"""
        logger.info(f"[GENERIC SMS] Would send SMS to {to_phone}: Token={voting_token}")

        return NotificationResult(
            success=True,
            message=f"SMS logged for {to_phone} (SMS not configured)",
            provider="generic",
            timestamp=datetime.now(timezone.utc),
        )


class NotificationService:
    """Main notification service that coordinates SMS and email"""

    def __init__(self):
        self.email_service = EmailService()
        self.sms_service = SMSService()

    async def send_voting_token(
        self,
        voter_data: Dict[str, Any],
        voting_token: str,
        voting_url: str,
        election_name: str = "Election",
        methods: List[str] = ["email", "sms"],
    ) -> Dict[str, NotificationResult]:
        """Send voting token via multiple methods"""
        results = {}

        voter_name = voter_data.get("name", "Voter")
        email = voter_data.get("email")
        phone = voter_data.get("phone")

        # Send email if email is provided and email method is requested
        if email and "email" in methods:
            results["email"] = await self.email_service.send_voting_token(
                email, voter_name, voting_token, voting_url, election_name
            )

        # Send SMS if phone is provided and SMS method is requested
        if phone and "sms" in methods:
            results["sms"] = await self.sms_service.send_voting_token(
                phone, voter_name, voting_token, voting_url, election_name
            )

        return results

    async def send_bulk_tokens(
        self,
        voters_data: List[Dict[str, Any]],
        voting_tokens: List[str],
        voting_url: str,
        election_name: str = "Election",
        methods: List[str] = ["email", "sms"],
    ) -> List[Dict[str, Any]]:
        """Send voting tokens to multiple voters"""
        results = []

        for i, voter_data in enumerate(voters_data):
            if i < len(voting_tokens):
                token_results = await self.send_voting_token(
                    voter_data, voting_tokens[i], voting_url, election_name, methods
                )

                results.append(
                    {
                        "voter_id": voter_data.get("id"),
                        "voter_name": voter_data.get("name"),
                        "token": voting_tokens[i],
                        "results": token_results,
                        "success": any(
                            result.success for result in token_results.values()
                        ),
                    }
                )

        return results
