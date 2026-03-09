"""Resend-only email utilities.

This project uses Resend for outbound mail delivery.

Exports used by the app:
- EmailSendResult
- EmailAuditLogger
- ResendConfig
- ResendEmailSender
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from datetime import datetime
from threading import Lock, Thread
from typing import Any, Callable, Optional

import requests

logger = logging.getLogger(__name__)


_EMAIL_PATTERN = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')


def _is_valid_email(email: str) -> bool:
    """Basic email validation."""
    if not email or len(email) > 254:
        return False
    return bool(_EMAIL_PATTERN.match(email.strip()))


class EmailSendResult:
    """Result of an email send operation."""
    
    def __init__(
        self,
        success: bool,
        recipient: str,
        subject: str,
        error: Optional[str] = None,
        attempt_count: int = 1,
        last_error_code: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.success = success
        self.recipient = recipient
        self.subject = subject
        self.error = error
        self.attempt_count = attempt_count
        self.last_error_code = last_error_code
        self.timestamp = timestamp or datetime.now()
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging."""
        return {
            'success': self.success,
            'recipient': self.recipient,
            'subject': self.subject,
            'error': self.error,
            'attempt_count': self.attempt_count,
            'last_error_code': self.last_error_code,
            'timestamp': self.timestamp.isoformat(),
        }


class ResendConfig:
    """Resend email configuration holder."""

    def __init__(
        self,
        api_key: str,
        from_address: str,
        reply_to: str | None = None,
        timeout_seconds: int = 30,
        max_retries: int = 3,
        retry_backoff_base: float = 2.0,
        base_url: str = "https://api.resend.com",
    ):
        self.api_key = (api_key or "").strip()
        self.from_address = (from_address or "").strip()
        self.reply_to = (reply_to or "").strip() or None
        self.timeout_seconds = max(5, min(int(timeout_seconds or 30), 120))
        self.max_retries = max(1, min(int(max_retries or 3), 5))
        self.retry_backoff_base = max(1.5, min(float(retry_backoff_base or 2.0), 3.0))
        self.base_url = (base_url or "https://api.resend.com").strip().rstrip("/")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.from_address)

    def validate(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "RESEND_API_KEY not configured"
        if not self.from_address:
            return False, "Resend from_address not configured"
        return True, ""


class ResendEmailSender:
    """Resend email sender with retry logic and audit-friendly results."""

    def __init__(self, config: ResendConfig):
        self.config = config
        self._lock = Lock()
        self._is_healthy = True
        is_valid, error = config.validate()
        if not is_valid:
            logger.warning(f"Resend configuration invalid: {error}")
            self._is_healthy = False

    def is_healthy(self) -> bool:
        return bool(self._is_healthy and self.config.is_configured())

    def send(
        self,
        recipient: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        reply_to: Optional[str] = None,
        attachments: list[tuple[str, str, bytes]] | None = None,
        from_address: Optional[str] = None,
    ) -> EmailSendResult:
        if not _is_valid_email(recipient):
            error_msg = f"Invalid recipient email: {recipient}"
            logger.error(error_msg)
            return EmailSendResult(
                success=False,
                recipient=recipient,
                subject=subject,
                error=error_msg,
                last_error_code="INVALID_EMAIL",
            )
        if not subject or not subject.strip():
            error_msg = "Subject cannot be empty"
            logger.error(error_msg)
            return EmailSendResult(
                success=False,
                recipient=recipient,
                subject=subject,
                error=error_msg,
                last_error_code="INVALID_SUBJECT",
            )
        if not html_body or not html_body.strip():
            error_msg = "Email body cannot be empty"
            logger.error(error_msg)
            return EmailSendResult(
                success=False,
                recipient=recipient,
                subject=subject,
                error=error_msg,
                last_error_code="INVALID_BODY",
            )

        if not self.is_healthy():
            error_msg = "Resend is not configured"
            logger.error(error_msg)
            return EmailSendResult(
                success=False,
                recipient=recipient,
                subject=subject,
                error=error_msg,
                last_error_code="RESEND_NOT_CONFIGURED",
            )

        last_error = None
        last_error_code = None

        for attempt in range(1, self.config.max_retries + 1):
            try:
                self._send_attempt(
                    recipient=recipient,
                    subject=subject,
                    html_body=html_body,
                    text_body=text_body,
                    reply_to=reply_to,
                    attachments=attachments,
                    from_address=from_address,
                )
                logger.info(
                    "Email sent successfully (Resend)",
                    extra={
                        'recipient': recipient,
                        'subject': subject,
                        'attempt': attempt,
                    },
                )
                return EmailSendResult(
                    success=True,
                    recipient=recipient,
                    subject=subject,
                    attempt_count=attempt,
                )
            except requests.Timeout as e:
                last_error = str(e)
                last_error_code = "RESEND_TIMEOUT"
                logger.warning(
                    f"Resend timeout (attempt {attempt}/{self.config.max_retries}): {e}",
                    extra={'recipient': recipient, 'subject': subject},
                )
            except requests.RequestException as e:
                last_error = str(e)
                last_error_code = "RESEND_REQUEST_ERROR"
                logger.warning(
                    f"Resend request error (attempt {attempt}/{self.config.max_retries}): {e}",
                    extra={'recipient': recipient, 'subject': subject},
                )
            except Exception as e:
                last_error = str(e)
                last_error_code = "RESEND_UNKNOWN_ERROR"
                logger.exception(
                    f"Unexpected error sending email via Resend (attempt {attempt}): {e}",
                    extra={'recipient': recipient, 'subject': subject},
                )
                break

            if attempt < self.config.max_retries:
                delay = self.config.retry_backoff_base ** (attempt - 1)
                logger.info(f"Waiting {delay:.1f}s before retry...")
                time.sleep(delay)

        error_msg = f"Failed to send email after {self.config.max_retries} attempts: {last_error}"
        logger.error(
            error_msg,
            extra={
                'recipient': recipient,
                'subject': subject,
                'error_code': last_error_code,
            },
        )
        return EmailSendResult(
            success=False,
            recipient=recipient,
            subject=subject,
            error=error_msg,
            attempt_count=self.config.max_retries,
            last_error_code=last_error_code,
        )

    def send_async(
        self,
        recipient: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        reply_to: Optional[str] = None,
        on_complete: Optional[Callable[[EmailSendResult], None]] = None,
        attachments: list[tuple[str, str, bytes]] | None = None,
        from_address: Optional[str] = None,
    ) -> None:
        def worker():
            result = self.send(
                recipient=recipient,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
                reply_to=reply_to,
                attachments=attachments,
                from_address=from_address,
            )
            if on_complete:
                try:
                    on_complete(result)
                except Exception as e:
                    logger.exception(f"Error in email completion callback: {e}")

        try:
            thread = Thread(target=worker, daemon=True, name=f"resend-email-{recipient}")
            thread.start()
        except Exception as e:
            logger.error(f"Failed to start email thread: {e}")

    def _send_attempt(
        self,
        *,
        recipient: str,
        subject: str,
        html_body: str,
        text_body: Optional[str],
        reply_to: Optional[str],
        attachments: list[tuple[str, str, bytes]] | None,
        from_address: Optional[str],
    ) -> None:
        url = f"{self.config.base_url}/emails"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        final_reply_to = (reply_to or self.config.reply_to or "").strip() or None
        if final_reply_to and not _is_valid_email(final_reply_to):
            final_reply_to = None

        final_from = (from_address or self.config.from_address or "").strip()
        if not final_from:
            raise requests.RequestException("Resend from address is not configured")

        payload: dict[str, Any] = {
            "from": final_from,
            "to": [recipient],
            "subject": subject,
            "html": html_body,
        }
        if text_body:
            payload["text"] = text_body
        if final_reply_to:
            payload["reply_to"] = final_reply_to

        if attachments:
            resend_attachments: list[dict[str, str]] = []
            for filename, content_type, data in attachments:
                if not filename or data is None:
                    continue
                resend_attachments.append({
                    "filename": str(filename),
                    "content": base64.b64encode(data).decode("ascii"),
                    **({"content_type": str(content_type)} if content_type else {}),
                })
            if resend_attachments:
                payload["attachments"] = resend_attachments

        logger.info(f"Sending email to {recipient} via Resend API...")
        logger.debug(f"Resend payload: from={final_from}, to={recipient}, subject={subject}")
        
        resp = requests.post(url, headers=headers, json=payload, timeout=self.config.timeout_seconds)
        
        # Log response details
        logger.info(f"Resend API response: status={resp.status_code}")
        
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            
            # Provide helpful error messages for common issues
            error_msg = f"Resend error {resp.status_code}: {detail}"
            logger.error(f"Resend API error: {error_msg}")
            
            # Check if using test domain
            if 'onboarding@resend.dev' in final_from.lower():
                logger.error(
                    f"\u26a0 IMPORTANT: You are using Resend's test domain (onboarding@resend.dev). "
                    f"This domain can ONLY send emails to verified addresses in your Resend dashboard. "
                    f"To send to ANY email address, you must add and verify your own domain. "
                    f"Visit https://resend.com/domains to set up your domain."
                )
            
            raise requests.RequestException(error_msg)
        else:
            logger.info(f"\u2713 Email successfully queued with Resend for {recipient}")



class EmailAuditLogger:
    """Log email send operations for audit and debugging."""
    
    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file
        self._lock = Lock()
    
    def log_send(self, result: EmailSendResult) -> None:
        """Log email send result."""
        try:
            entry = {
                'timestamp': result.timestamp.isoformat(),
                'recipient': result.recipient,
                'subject': result.subject,
                'success': result.success,
                'error': result.error,
                'attempt_count': result.attempt_count,
                'error_code': result.last_error_code,
            }
            
            if self.log_file:
                with self._lock:
                    with open(self.log_file, 'a', encoding='utf-8') as f:
                        f.write(json.dumps(entry) + '\n')
            
            logger.info(f"Email audit: {json.dumps(entry)}")
        except Exception as e:
            logger.exception(f"Failed to log email result: {e}")
