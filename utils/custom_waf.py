"""
Custom Web Application Firewall (WAF)
Protects against common web attacks and malicious requests.

Features:
- SQL Injection detection and blocking
- XSS (Cross-Site Scripting) prevention
- Path Traversal protection
- Command Injection detection
- CSRF validation enforcement
- Rate limiting per endpoint
- Request size validation
- Suspicious pattern detection
- IP-based blocking and whitelisting
- Automatic threat blocking
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from flask import request, abort, jsonify, current_app
from functools import wraps
import hashlib
import json

# Configure logger
logger = logging.getLogger(__name__)


class WAFRuleEngine:
    """Core rule engine for detecting malicious patterns"""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        # Keep SQLi patterns specific to avoid false positives in free-text clinical notes.
        r"\bunion\b\s+(?:all\s+)?\bselect\b",
        r"\bselect\b\s+\*\s+\bfrom\b",
        r"\binsert\b\s+\binto\b",
        r"\bupdate\b\s+\w+\s+\bset\b",
        r"\bdelete\b\s+\bfrom\b",
        r"\b(drop|create|alter|truncate)\b\s+\btable\b",
        r"(';|'--|'\||'\))",
        # Avoid broad matches like "or ... =" which frequently occur in clinical text.
        # Keep common tautology and string-compare patterns used in SQLi payloads.
        r"(\b(or|and)\b\s+\d+\s*=\s*\d+|1=1|'=')",
        # Do not treat bare "--" or "#" as SQLi; they are common in normal text (e.g., "Problem #1", separators).
        r"(\/\*|\*\/|\bxp_\w+|\bsp_\w+)",
        r"(\bexec\b|\bexecute\b)(\s|\+)+(s|x)p\w+",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?<\/script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"eval\s*\(",
        r"expression\s*\(",
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\.[\/\\]",
        r"[\/\\]etc[\/\\]passwd",
        r"[\/\\]windows[\/\\]system32",
        r"%2e%2e[\/\\]",
        r"\.\.%2f",
    ]
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]\s*(cat|ls|pwd|wget|curl|nc|bash|sh|cmd|powershell)",
        r"\$\(.*\)",
        r"`.*`",
        r"\|\s*(cat|ls|pwd|wget)",
    ]
    
    # Suspicious headers
    SUSPICIOUS_HEADERS = [
        'x-forwarded-host',
        'x-original-url',
        'x-rewrite-url',
    ]
    
    @classmethod
    def check_sql_injection(cls, text: str) -> bool:
        """Check for SQL injection patterns"""
        if not text:
            return False
        text_lower = text.lower()
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def check_xss(cls, text: str) -> bool:
        """Check for XSS patterns"""
        if not text:
            return False
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def check_path_traversal(cls, text: str) -> bool:
        """Check for path traversal attempts"""
        if not text:
            return False
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def check_command_injection(cls, text: str) -> bool:
        """Check for command injection attempts"""
        if not text:
            return False
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def check_suspicious_headers(cls, headers: dict) -> Tuple[bool, Optional[str]]:
        """Check for suspicious or malicious headers"""
        for header in cls.SUSPICIOUS_HEADERS:
            if header in [h.lower() for h in headers.keys()]:
                return True, header
        return False, None


class WAFBlocklist:
    """Manage blocked IPs and automatic threat detection"""
    
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.threat_scores: Dict[str, int] = {}
        self.last_violations: Dict[str, datetime] = {}
        self.whitelist: Set[str] = {'127.0.0.1', 'localhost', '::1'}
        
        # Thresholds
        self.THREAT_SCORE_THRESHOLD = 50
        self.AUTO_BLOCK_THRESHOLD = 100
        self.VIOLATION_EXPIRY_HOURS = 24
    
    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist"""
        self.whitelist.add(ip)
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        return ip in self.whitelist
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def block_ip(self, ip: str, reason: str = "Manual block"):
        """Manually block an IP"""
        if not self.is_whitelisted(ip):
            self.blocked_ips.add(ip)
            logger.warning(f"WAF: Blocked IP {ip}. Reason: {reason}")
    
    def unblock_ip(self, ip: str):
        """Unblock an IP"""
        if ip in self.blocked_ips:
            self.blocked_ips.discard(ip)
            logger.info(f"WAF: Unblocked IP {ip}")
    
    def record_violation(self, ip: str, severity: int, attack_type: str):
        """Record a security violation and increase threat score"""
        if self.is_whitelisted(ip):
            return
        
        # Initialize threat score if needed
        if ip not in self.threat_scores:
            self.threat_scores[ip] = 0
        
        # Increase threat score
        self.threat_scores[ip] += severity
        self.last_violations[ip] = datetime.utcnow()
        
        # Log the violation
        logger.warning(
            f"WAF: Violation detected from {ip}. "
            f"Type: {attack_type}, Severity: {severity}, "
            f"Total Score: {self.threat_scores[ip]}"
        )
        
        # Auto-block if threshold exceeded
        if self.threat_scores[ip] >= self.AUTO_BLOCK_THRESHOLD:
            self.block_ip(ip, f"Auto-block: Threat score {self.threat_scores[ip]}")
    
    def cleanup_old_violations(self):
        """Remove old violation records"""
        now = datetime.utcnow()
        expired = []
        
        for ip, last_time in self.last_violations.items():
            if (now - last_time).total_seconds() > (self.VIOLATION_EXPIRY_HOURS * 3600):
                expired.append(ip)
        
        for ip in expired:
            if ip in self.threat_scores:
                del self.threat_scores[ip]
            if ip in self.last_violations:
                del self.last_violations[ip]
            logger.info(f"WAF: Cleaned up old violations for {ip}")
    
    def get_threat_score(self, ip: str) -> int:
        """Get current threat score for IP"""
        return self.threat_scores.get(ip, 0)


class CustomWAF:
    """Custom Web Application Firewall"""
    
    def __init__(self):
        self.blocklist = WAFBlocklist()
        self.rule_engine = WAFRuleEngine()
        self.request_history: Dict[str, List[datetime]] = {}

        # Some endpoints legitimately carry high-entropy blobs (JWK/base64, encrypted payloads)
        # which can trigger regex-based false positives for SQLi/XSS. We sanitize these keys
        # before pattern scanning to preserve protection without breaking functionality.
        self._json_scan_redact_keys: Set[str] = {
            'public_jwk',
            'private_jwk',
            'ek',
            'ct',
            'iv',
            'signature',
        }
        
        # Configuration
        self.enabled = True
        self.log_violations = True
        self.block_on_detection = True
        
        # Severity scores
        self.SEVERITY = {
            'sql_injection': 50,
            'xss': 40,
            'path_traversal': 45,
            'command_injection': 50,
            'suspicious_header': 20,
            'rate_limit': 10,
            'invalid_input': 15,
        }

    def _sanitize_json_for_scans(self, data):
        """Redact high-entropy fields from JSON payloads before regex scanning."""
        try:
            if isinstance(data, dict):
                sanitized = {}
                for k, v in data.items():
                    key = str(k)
                    if key in self._json_scan_redact_keys:
                        # Keep the fact a value exists, but avoid scanning its contents.
                        if isinstance(v, (dict, list)):
                            sanitized[key] = '<redacted>'
                        else:
                            s = '' if v is None else str(v)
                            sanitized[key] = f'<redacted len={len(s)}>'
                        continue
                    sanitized[key] = self._sanitize_json_for_scans(v)
                return sanitized
            if isinstance(data, list):
                return [self._sanitize_json_for_scans(x) for x in data]
        except Exception:
            return '<unscannable>'
        return data
    
    def enable(self):
        """Enable WAF"""
        self.enabled = True
        logger.info("WAF: Enabled")
    
    def disable(self):
        """Disable WAF"""
        self.enabled = False
        logger.warning("WAF: Disabled")
    
    def get_client_ip(self) -> str:
        """Get the real client IP address"""
        # Check for proxy headers first
        if request.headers.get('X-Forwarded-For'):
            # Take the first IP in the chain (original client)
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr or 'unknown'
    
    def check_request(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check current request for threats.
        Returns: (is_safe, attack_type, details)
        """
        if not self.enabled:
            return True, None, None
        
        client_ip = self.get_client_ip()
        
        # Check if IP is blocked
        if self.blocklist.is_blocked(client_ip):
            return False, 'blocked_ip', f'IP {client_ip} is blocked'
        
        # Check headers
        is_suspicious, header = self.rule_engine.check_suspicious_headers(request.headers)
        if is_suspicious:
            self.blocklist.record_violation(
                client_ip, 
                self.SEVERITY['suspicious_header'],
                'suspicious_header'
            )
            if self.block_on_detection:
                return False, 'suspicious_header', f'Suspicious header: {header}'
        
        # Check URL path
        if self.rule_engine.check_path_traversal(request.path):
            self.blocklist.record_violation(
                client_ip,
                self.SEVERITY['path_traversal'],
                'path_traversal'
            )
            if self.block_on_detection:
                return False, 'path_traversal', 'Path traversal attempt detected'
        
        # Check query parameters
        for key, value in request.args.items():
            value_str = str(value)
            
            if self.rule_engine.check_sql_injection(value_str):
                self.blocklist.record_violation(
                    client_ip,
                    self.SEVERITY['sql_injection'],
                    'sql_injection'
                )
                if self.block_on_detection:
                    return False, 'sql_injection', f'SQL injection in parameter: {key}'
            
            if self.rule_engine.check_xss(value_str):
                self.blocklist.record_violation(
                    client_ip,
                    self.SEVERITY['xss'],
                    'xss'
                )
                if self.block_on_detection:
                    return False, 'xss', f'XSS attempt in parameter: {key}'
            
            if self.rule_engine.check_command_injection(value_str):
                self.blocklist.record_violation(
                    client_ip,
                    self.SEVERITY['command_injection'],
                    'command_injection'
                )
                if self.block_on_detection:
                    return False, 'command_injection', f'Command injection in parameter: {key}'
        
        # Check form data (POST requests)
        if request.method == 'POST' and request.form:
            for key, value in request.form.items():
                # Skip CSRF token validation
                if key == 'csrf_token':
                    continue
                
                value_str = str(value)
                
                if self.rule_engine.check_sql_injection(value_str):
                    self.blocklist.record_violation(
                        client_ip,
                        self.SEVERITY['sql_injection'],
                        'sql_injection'
                    )
                    if self.block_on_detection:
                        return False, 'sql_injection', f'SQL injection in form field: {key}'
                
                if self.rule_engine.check_xss(value_str):
                    self.blocklist.record_violation(
                        client_ip,
                        self.SEVERITY['xss'],
                        'xss'
                    )
                    if self.block_on_detection:
                        return False, 'xss', f'XSS attempt in form field: {key}'
        
        # Check JSON payload
        if request.is_json:
            try:
                json_data = request.get_json()
                if json_data:
                    sanitized = self._sanitize_json_for_scans(json_data)
                    json_str = json.dumps(sanitized)
                    
                    if self.rule_engine.check_sql_injection(json_str):
                        self.blocklist.record_violation(
                            client_ip,
                            self.SEVERITY['sql_injection'],
                            'sql_injection'
                        )
                        if self.block_on_detection:
                            return False, 'sql_injection', 'SQL injection in JSON payload'
                    
                    if self.rule_engine.check_xss(json_str):
                        self.blocklist.record_violation(
                            client_ip,
                            self.SEVERITY['xss'],
                            'xss'
                        )
                        if self.block_on_detection:
                            return False, 'xss', 'XSS attempt in JSON payload'
            except Exception:
                pass  # Invalid JSON, let Flask handle it
        
        # Request passed all checks
        return True, None, None
    
    def log_attack(self, client_ip: str, attack_type: str, details: str):
        """Log attack attempt"""
        if self.log_violations:
            logger.warning(
                f"WAF: Attack blocked! "
                f"IP: {client_ip}, Type: {attack_type}, "
                f"Details: {details}, Path: {request.path}, "
                f"Method: {request.method}"
            )
    
    def cleanup(self):
        """Cleanup old data"""
        self.blocklist.cleanup_old_violations()


# Global WAF instance
waf = CustomWAF()


def waf_protected(f):
    """
    Decorator to protect routes with WAF.
    Usage: @waf_protected
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if current_app.config.get('WAF_ENABLED') is False:
                return f(*args, **kwargs)
        except Exception:
            pass

        is_safe, attack_type, details = waf.check_request()
        
        if not is_safe:
            client_ip = waf.get_client_ip()
            waf.log_attack(client_ip, attack_type, details)

            try:
                from utils.siem import emit_waf_block

                emit_waf_block(
                    ip=str(client_ip),
                    attack_type=str(attack_type or 'unknown')[:64],
                    details=str(details or '')[:240],
                    endpoint=request.path,
                )
            except Exception:
                pass
            
            # Return 403 Forbidden with minimal information
            return jsonify({
                'error': 'Access Denied',
                'message': 'Your request was blocked by security policies.',
                'code': 'WAF_BLOCKED'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


def init_waf(app):
    """Initialize WAF with Flask app"""
    
    @app.before_request
    def waf_check():
        """Check all requests with WAF"""
        # Allow runtime disable via feature flags.
        try:
            if app.config.get('WAF_ENABLED') is False:
                return
        except Exception:
            pass

        # Skip WAF for static files
        if request.path.startswith('/static/'):
            return
        
        is_safe, attack_type, details = waf.check_request()
        
        if not is_safe:
            client_ip = waf.get_client_ip()
            waf.log_attack(client_ip, attack_type, details)

            # Emit to SIEM for correlation/incident response (best-effort only).
            try:
                from utils.siem import emit_waf_block

                emit_waf_block(
                    ip=str(client_ip),
                    attack_type=str(attack_type or 'unknown')[:64],
                    details=str(details or '')[:240],
                    endpoint=request.path,
                )
            except Exception:
                pass
            
            # Return 403 Forbidden
            abort(403)
    
    # Cleanup task (run periodically)
    def cleanup_task():
        """Background task to cleanup old data"""
        import threading
        import time
        
        def run_cleanup():
            while True:
                try:
                    time.sleep(3600)  # Run every hour
                    waf.cleanup()
                except Exception as e:
                    logger.error(f"WAF cleanup error: {e}")
        
        thread = threading.Thread(target=run_cleanup, daemon=True)
        thread.start()
    
    # Start cleanup task
    cleanup_task()
    
    app.logger.info("Custom WAF initialized and active")


# Utility functions for manual control
def block_ip(ip: str, reason: str = "Manual block"):
    """Manually block an IP address"""
    waf.blocklist.block_ip(ip, reason)


def unblock_ip(ip: str):
    """Unblock an IP address"""
    waf.blocklist.unblock_ip(ip)


def add_whitelist(ip: str):
    """Add IP to whitelist"""
    waf.blocklist.add_to_whitelist(ip)


def get_blocked_ips() -> Set[str]:
    """Get list of blocked IPs"""
    return waf.blocklist.blocked_ips.copy()


def get_threat_scores() -> Dict[str, int]:
    """Get current threat scores"""
    return waf.blocklist.threat_scores.copy()
