"""
Email template helpers for production-ready emails with consistent branding and formatting.

Features:
- Consistent HTML/text formatting
- Responsive layouts
- Security headers and footers
- Unsubscribe links
- Fallback text versions
"""

from html import escape
from datetime import datetime


class EmailTemplate:
    """Base email template with branding and formatting."""
    
    # Branding colors
    PRIMARY_COLOR = "#667eea"
    SECONDARY_COLOR = "#764ba2"
    DANGER_COLOR = "#f56565"
    SUCCESS_COLOR = "#38a169"
    WARNING_COLOR = "#ecc94b"
    
    # Default sender info
    SYSTEM_NAME = "Makokha Medical Centre"
    SUPPORT_EMAIL = "support@makokha.local"
    
    @staticmethod
    def header() -> str:
        """Common email header."""
        return (
            "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>"
            "<div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); "
            "padding: 20px; text-align: center; border-radius: 8px 8px 0 0;'>"
            "<h1 style='color: white; margin: 0;'>Makokha Medical Centre</h1>"
            "</div>"
            "<div style='border: 1px solid #e2e8f0; border-top: none; padding: 20px;'>"
        )
    
    @staticmethod
    def footer(show_support: bool = True) -> str:
        """Common email footer."""
        footer_parts = [
            "<hr style='margin: 20px 0; border: none; border-top: 1px solid #e2e8f0;' />",
            "<div style='font-size: 12px; color: #a0aec0; line-height: 1.6;'>",
        ]
        
        if show_support:
            footer_parts.append(
                f"<p style='margin: 0 0 10px 0;'>"
                f"<strong>Questions?</strong> Contact support at "
                f"<a href='mailto:{EmailTemplate.SUPPORT_EMAIL}' style='color: #667eea; text-decoration: none;'>"
                f"{EmailTemplate.SUPPORT_EMAIL}</a></p>"
            )
        
        footer_parts.extend([
            "<p style='margin: 0;'>This is an automated email from Makokha Medical Centre system. "
            "Please do not reply directly to this email.</p>",
            f"<p style='margin: 10px 0 0 0; color: #cbd5e0;'>{datetime.now().strftime('%Y-%m-%d %H:%M')} EAT</p>",
            "</div>",
            "</div>",
            "</div>",
        ])
        
        return "".join(footer_parts)
    
    @staticmethod
    def section_title(title: str) -> str:
        """Section title styling."""
        return f"<h2 style='color: #2d3748; margin: 20px 0 10px 0; font-size: 20px;'>{escape(title)}</h2>"
    
    @staticmethod
    def alert_box(message: str, alert_type: str = "info") -> str:
        """Alert/info box styling."""
        colors = {
            "success": ("#38a169", "#c6f6d5"),
            "warning": ("#ecc94b", "#fefcbf"),
            "danger": ("#f56565", "#fed7d7"),
            "info": ("#4299e1", "#bee3f8"),
        }
        text_color, bg_color = colors.get(alert_type, colors["info"])
        
        return (
            f"<div style='background: {bg_color}; border-left: 4px solid {text_color}; "
            f"padding: 12px 16px; margin: 16px 0; border-radius: 4px;'>"
            f"<p style='margin: 0; color: {text_color}; font-weight: 500;'>{escape(message)}</p>"
            f"</div>"
        )
    
    @staticmethod
    def code_box(code: str, size: str = "large") -> str:
        """Large code/token display box."""
        font_sizes = {"small": "20px", "medium": "28px", "large": "36px"}
        font_size = font_sizes.get(size, "36px")
        
        letter_spacing = "4px" if size == "small" else "6px" if size == "medium" else "8px"
        
        return (
            f"<div style='text-align: center; margin: 20px 0;'>"
            f"<div style='font-size: {font_size}; letter-spacing: {letter_spacing}; "
            f"font-weight: 700; padding: 20px; background: #f7fafc; border: 2px solid #e2e8f0; "
            f"border-radius: 8px; font-family: monospace; color: #2d3748;'>"
            f"{escape(str(code))}"
            f"</div>"
            f"</div>"
        )
    
    @staticmethod
    def button(text: str, url: str, color: str = "primary") -> str:
        """Call-to-action button."""
        colors = {
            "primary": "#667eea",
            "secondary": "#4299e1",
            "success": "#38a169",
            "danger": "#f56565",
        }
        bg_color = colors.get(color, colors["primary"])
        
        return (
            f"<div style='text-align: center; margin: 20px 0;'>"
            f"<a href='{escape(url)}' style='display: inline-block; padding: 12px 28px; "
            f"background-color: {bg_color}; color: white; text-decoration: none; "
            f"border-radius: 6px; font-weight: bold; font-size: 16px;'>"
            f"{escape(text)}"
            f"</a>"
            f"</div>"
        )
    
    @staticmethod
    def info_box(items: list[tuple[str, str]]) -> str:
        """Display key-value information."""
        html_parts = ["<div style='margin: 16px 0; background: #f7fafc; padding: 16px; border-radius: 6px;'>"]
        
        for key, value in items:
            html_parts.append(
                f"<p style='margin: 8px 0; line-height: 1.6;'>"
                f"<strong>{escape(key)}:</strong> {escape(str(value))}"
                f"</p>"
            )
        
        html_parts.append("</div>")
        return "".join(html_parts)
    
    @staticmethod
    def security_warning(message: str) -> str:
        """Security warning box."""
        return (
            f"<div style='background: #fed7d7; border-left: 4px solid #f56565; "
            f"padding: 12px 16px; margin: 16px 0; border-radius: 4px;'>"
            f"<p style='margin: 0; color: #c53030; font-weight: 500;'>"
            f"🔒 <strong>Security:</strong> {escape(message)}"
            f"</p>"
            f"</div>"
        )


class OTPEmailTemplate:
    """Email template for OTP codes."""
    
    @staticmethod
    def verification_otp(otp_code: str, minutes_valid: int = 10) -> tuple[str, str]:
        """Generate OTP verification email."""
        html = (
            f"{EmailTemplate.header()}"
            f"{EmailTemplate.section_title('Verify Your Email Address')}"
            f"<p>Welcome! To complete your registration, please verify your email by entering the code below.</p>"
            f"{EmailTemplate.code_box(otp_code)}"
            f"<p style='text-align: center; color: #718096; margin-top: 16px;'>"
            f"This code expires in <strong>{minutes_valid} minutes</strong>"
            f"</p>"
            f"{EmailTemplate.alert_box('If you did not request this verification, please ignore this email.', 'info')}"
            f"{EmailTemplate.footer()}"
        )
        
        text = (
            f"Verify Your Email Address\n\n"
            f"Your verification code is: {otp_code}\n\n"
            f"This code expires in {minutes_valid} minutes.\n\n"
            f"If you did not request this, please ignore this email."
        )
        
        return html, text
    
    @staticmethod
    def backup_otp(otp_code: str, minutes_valid: int = 10) -> tuple[str, str]:
        """Generate backup access OTP email."""
        html = (
            f"{EmailTemplate.header()}"
            f"{EmailTemplate.section_title('🔐 Backup Access Verification')}"
            f"<p>You've requested access to your backup account. Use the code below to verify:</p>"
            f"{EmailTemplate.code_box(otp_code)}"
            f"<p style='text-align: center; color: #718096; margin-top: 16px;'>"
            f"This code expires in <strong>{minutes_valid} minutes</strong>"
            f"</p>"
            f"{EmailTemplate.security_warning('Never share this code with anyone. We will never ask for it via email.')}"
            f"{EmailTemplate.footer()}"
        )
        
        text = (
            f"Backup Access Verification\n\n"
            f"Your verification code is: {otp_code}\n\n"
            f"This code expires in {minutes_valid} minutes.\n\n"
            f"For security, never share this code. If you didn't request this, "
            f"someone may be trying to access your account."
        )
        
        return html, text


class PasswordResetEmailTemplate:
    """Email template for password resets."""
    
    @staticmethod
    def reset_request(reset_url: str, hours_valid: int = 1) -> tuple[str, str]:
        """Generate password reset email."""
        hour_suffix = "s" if hours_valid != 1 else ""
        html = (
            f"{EmailTemplate.header()}"
            f"{EmailTemplate.section_title('🔑 Password Reset Request')}"
            f"<p>We received a request to reset your password. Click the button below to proceed:</p>"
            f"{EmailTemplate.button('Reset Password', reset_url, color='primary')}"
            f"<p style='text-align: center; color: #718096; margin-top: 16px;'>"
            f"This link expires in <strong>{hours_valid} hour{hour_suffix}</strong>"
            f"</p>"
            f'{EmailTemplate.security_warning("If you didn\'t request this, your password will remain unchanged.")}'
            f"{EmailTemplate.footer()}"
        )
        
        text = (
            f"Password Reset Request\n\n"
            f"Click the link below to reset your password:\n"
            f"{reset_url}\n\n"
            f"This link expires in {hours_valid} hour{hour_suffix}.\n\n"
            f"If you didn't request this, please ignore this email."
        )
        
        return html, text
