"""
Adaptive Authentication System
Dynamically adjusts authentication requirements based on risk factors.

Features:
- Risk-based authentication
- Device fingerprinting
- Location-based risk assessment
- Behavioral analysis
- Time-based risk factors
- Anomaly detection
- Step-up authentication when needed
- Trust score calculation
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import re


class DeviceFingerprint:
    """Generate and verify device fingerprints"""
    
    @staticmethod
    def generate_fingerprint(user_agent: str, ip_address: str, accept_language: str = '') -> str:
        """
        Generate a device fingerprint.
        
        Args:
            user_agent: Browser User-Agent string
            ip_address: Client IP address
            accept_language: Accept-Language header
            
        Returns:
            Device fingerprint hash
        """
        # Combine device characteristics
        fingerprint_data = f"{user_agent}|{ip_address}|{accept_language}"
        
        # Hash the fingerprint
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    @staticmethod
    def is_known_device(current_fingerprint: str, known_fingerprints: List[str]) -> bool:
        """Check if device fingerprint is known"""
        return current_fingerprint in known_fingerprints


class RiskAssessment:
    """Assess authentication risk level"""
    
    # Risk scores (0-100, higher = more risky)
    RISK_LEVELS = {
        'LOW': (0, 30),
        'MEDIUM': (31, 60),
        'HIGH': (61, 85),
        'CRITICAL': (86, 100)
    }
    
    def __init__(self):
        self.risk_factors = {
            'unknown_device': 30,
            'unusual_location': 25,
            'unusual_time': 15,
            'rapid_location_change': 40,
            'suspicious_ip': 35,
            'failed_attempts': 20,
            'tor_vpn_detected': 30,
            'unusual_behavior': 25,
        }
    
    def calculate_risk_score(self, factors: Dict[str, bool]) -> Tuple[int, str]:
        """
        Calculate risk score based on detected factors.
        
        Args:
            factors: Dictionary of risk factors {factor_name: is_present}
            
        Returns:
            (risk_score, risk_level)
        """
        total_score = 0
        
        for factor, is_present in factors.items():
            if is_present and factor in self.risk_factors:
                total_score += self.risk_factors[factor]
        
        # Cap at 100
        total_score = min(total_score, 100)
        
        # Determine risk level
        risk_level = 'LOW'
        for level, (min_score, max_score) in self.RISK_LEVELS.items():
            if min_score <= total_score <= max_score:
                risk_level = level
                break
        
        return total_score, risk_level
    
    def assess_device(self, current_fingerprint: str, known_fingerprints: List[str]) -> bool:
        """Check if device is unknown"""
        return not DeviceFingerprint.is_known_device(current_fingerprint, known_fingerprints)
    
    def assess_location(self, current_ip: str, known_ips: List[str]) -> bool:
        """Check if location (IP) is unusual"""
        # Simple check - in production, use GeoIP
        return current_ip not in known_ips
    
    def assess_time(self, current_hour: int, typical_hours: List[int]) -> bool:
        """Check if login time is unusual"""
        if not typical_hours:
            return False
        return current_hour not in typical_hours
    
    def detect_rapid_location_change(
        self, 
        current_ip: str, 
        last_login_ip: str, 
        time_since_last_login: timedelta
    ) -> bool:
        """
        Detect impossible travel (rapid location change).
        
        Args:
            current_ip: Current IP address
            last_login_ip: Last login IP address
            time_since_last_login: Time since last login
            
        Returns:
            True if rapid change detected
        """
        # If IPs are different and time is less than 1 hour
        if current_ip != last_login_ip and time_since_last_login < timedelta(hours=1):
            # In production, check actual geographic distance
            return True
        return False
    
    def check_suspicious_ip(self, ip_address: str) -> bool:
        """
        Check if IP is from known suspicious source.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if suspicious
        """
        # Known bad IP ranges (example)
        suspicious_patterns = [
            r'^0\.0\.0\.0$',  # Invalid
            r'^127\.',        # Localhost (if from external)
            r'^10\.',         # Private (if claiming external)
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, ip_address):
                return True
        
        return False


class LoginHistory:
    """Track and analyze login history"""
    
    def __init__(self):
        self.history: Dict[int, List[dict]] = {}
    
    def record_login(
        self, 
        user_id: int, 
        ip_address: str, 
        device_fingerprint: str,
        success: bool,
        timestamp: Optional[datetime] = None
    ):
        """Record a login attempt"""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        if user_id not in self.history:
            self.history[user_id] = []
        
        self.history[user_id].append({
            'ip': ip_address,
            'device': device_fingerprint,
            'success': success,
            'timestamp': timestamp
        })
        
        # Keep only last 100 entries per user
        if len(self.history[user_id]) > 100:
            self.history[user_id] = self.history[user_id][-100:]
    
    def get_known_devices(self, user_id: int) -> List[str]:
        """Get list of known device fingerprints for user"""
        if user_id not in self.history:
            return []
        
        devices = set()
        for entry in self.history[user_id]:
            if entry['success']:
                devices.add(entry['device'])
        
        return list(devices)
    
    def get_known_ips(self, user_id: int) -> List[str]:
        """Get list of known IP addresses for user"""
        if user_id not in self.history:
            return []
        
        ips = set()
        for entry in self.history[user_id]:
            if entry['success']:
                ips.add(entry['ip'])
        
        return list(ips)
    
    def get_typical_hours(self, user_id: int) -> List[int]:
        """Get typical login hours for user"""
        if user_id not in self.history:
            return []
        
        hours = {}
        for entry in self.history[user_id]:
            if entry['success']:
                hour = entry['timestamp'].hour
                hours[hour] = hours.get(hour, 0) + 1
        
        # Return hours that account for 80% of logins
        total_logins = sum(hours.values())
        threshold = total_logins * 0.8
        
        sorted_hours = sorted(hours.items(), key=lambda x: x[1], reverse=True)
        typical = []
        count = 0
        
        for hour, freq in sorted_hours:
            typical.append(hour)
            count += freq
            if count >= threshold:
                break
        
        return typical
    
    def get_failed_attempts_count(self, user_id: int, time_window: timedelta) -> int:
        """Count failed login attempts in time window"""
        if user_id not in self.history:
            return 0
        
        now = datetime.utcnow()
        cutoff = now - time_window
        
        count = 0
        for entry in self.history[user_id]:
            if not entry['success'] and entry['timestamp'] >= cutoff:
                count += 1
        
        return count
    
    def get_last_login(self, user_id: int) -> Optional[dict]:
        """Get last successful login"""
        if user_id not in self.history:
            return None
        
        for entry in reversed(self.history[user_id]):
            if entry['success']:
                return entry
        
        return None


class AdaptiveAuthentication:
    """Adaptive Authentication System"""
    
    def __init__(self):
        self.risk_assessment = RiskAssessment()
        self.login_history = LoginHistory()
        self.trust_scores: Dict[int, int] = {}
        
        # Configuration
        self.enabled = True
        self.require_mfa_on_high_risk = True
        self.require_mfa_on_critical_risk = True
        self.block_on_critical_risk = False  # Just require additional auth
    
    def enable(self):
        """Enable adaptive authentication"""
        self.enabled = True
    
    def disable(self):
        """Disable adaptive authentication"""
        self.enabled = False
    
    def assess_login_risk(
        self,
        user_id: int,
        ip_address: str,
        user_agent: str,
        accept_language: str = '',
        known_devices: Optional[List[str]] = None,
        known_ips: Optional[List[str]] = None,
        typical_hours: Optional[List[int]] = None,
        failed_attempts: Optional[int] = None,
    ) -> Tuple[int, str, Dict[str, bool]]:
        """
        Assess risk level for a login attempt.
        
        Args:
            user_id: User attempting to login
            ip_address: Client IP address
            user_agent: Browser User-Agent
            accept_language: Accept-Language header
            
        Returns:
            (risk_score, risk_level, risk_factors)
        """
        if not self.enabled:
            return 0, 'LOW', {}
        
        # Generate device fingerprint
        device_fingerprint = DeviceFingerprint.generate_fingerprint(
            user_agent, ip_address, accept_language
        )
        
        # Get user's history unless caller provided persisted overrides
        if known_devices is None:
            known_devices = self.login_history.get_known_devices(user_id)
        if known_ips is None:
            known_ips = self.login_history.get_known_ips(user_id)
        if typical_hours is None:
            typical_hours = self.login_history.get_typical_hours(user_id)

        failed_attempts_present = (
            (failed_attempts is not None and failed_attempts >= 3)
            or (self.login_history.get_failed_attempts_count(user_id, timedelta(hours=1)) >= 3)
        )
        last_login = self.login_history.get_last_login(user_id)
        
        # Detect risk factors
        risk_factors = {
            'unknown_device': self.risk_assessment.assess_device(device_fingerprint, known_devices),
            'unusual_location': self.risk_assessment.assess_location(ip_address, known_ips),
            'unusual_time': self.risk_assessment.assess_time(datetime.utcnow().hour, typical_hours),
            'suspicious_ip': self.risk_assessment.check_suspicious_ip(ip_address),
            'failed_attempts': failed_attempts_present,
        }
        
        # Check rapid location change
        if last_login:
            time_since_last = datetime.utcnow() - last_login['timestamp']
            risk_factors['rapid_location_change'] = self.risk_assessment.detect_rapid_location_change(
                ip_address, last_login['ip'], time_since_last
            )
        else:
            risk_factors['rapid_location_change'] = False
        
        # Calculate risk score
        risk_score, risk_level = self.risk_assessment.calculate_risk_score(risk_factors)
        
        return risk_score, risk_level, risk_factors

    def calculate_risk_score(self, factors: Dict[str, bool]) -> Tuple[int, str]:
        """Calculate a risk score and risk level from pre-computed risk factors.

        This is a supported public API used by the Flask login flow.

        Args:
            factors: Mapping of {risk_factor_name: is_present}. Unknown factor names
                are ignored. Values are coerced to bool.

        Returns:
            (risk_score, risk_level)
        """
        if not self.enabled:
            return 0, 'LOW'

        if factors is None:
            return 0, 'LOW'

        if not isinstance(factors, dict):
            raise TypeError("factors must be a dict of {str: bool}")

        normalized: Dict[str, bool] = {}
        for key, value in factors.items():
            # Defensive: allow non-str keys (e.g., enums) but normalize to str
            normalized[str(key)] = bool(value)

        # Keep scoring logic centralized in RiskAssessment
        return self.risk_assessment.calculate_risk_score(normalized)
    
    def determine_auth_requirements(
        self,
        risk_score: int,
        risk_level: str
    ) -> Dict[str, bool]:
        """
        Determine what authentication is required based on risk.
        
        Args:
            risk_score: Calculated risk score
            risk_level: Risk level (LOW/MEDIUM/HIGH/CRITICAL)
            
        Returns:
            Dictionary of requirements
        """
        requirements = {
            'password_required': True,
            'mfa_required': False,
            'email_verification_required': False,
            'security_questions_required': False,
            'admin_approval_required': False,
            'block_login': False
        }
        
        if risk_level == 'MEDIUM':
            # Low friction, just log
            pass
        
        elif risk_level == 'HIGH':
            # Require MFA if enabled
            requirements['mfa_required'] = self.require_mfa_on_high_risk
        
        elif risk_level == 'CRITICAL':
            # Require MFA and additional verification
            requirements['mfa_required'] = self.require_mfa_on_critical_risk
            requirements['email_verification_required'] = True
            
            if self.block_on_critical_risk:
                requirements['block_login'] = True
        
        return requirements
    
    def record_login_attempt(
        self,
        user_id: int,
        ip_address: str,
        user_agent: str,
        success: bool,
        accept_language: str = ''
    ):
        """Record a login attempt"""
        if not self.enabled:
            return
        device_fingerprint = DeviceFingerprint.generate_fingerprint(
            user_agent, ip_address, accept_language
        )
        
        self.login_history.record_login(
            user_id, ip_address, device_fingerprint, success
        )
        
        # Update trust score
        if success:
            # Increase trust on successful login from known device
            known_devices = self.login_history.get_known_devices(user_id)
            if device_fingerprint in known_devices:
                self.trust_scores[user_id] = min(
                    self.trust_scores.get(user_id, 50) + 5, 100
                )
            else:
                # New device, slightly decrease trust
                self.trust_scores[user_id] = max(
                    self.trust_scores.get(user_id, 50) - 10, 0
                )
        else:
            # Decrease trust on failed login
            self.trust_scores[user_id] = max(
                self.trust_scores.get(user_id, 50) - 15, 0
            )
    
    def get_trust_score(self, user_id: int) -> int:
        """Get current trust score for user (0-100)"""
        return self.trust_scores.get(user_id, 50)


# Global instance
adaptive_auth = AdaptiveAuthentication()


# Utility functions
def assess_login_risk(user_id: int, ip_address: str, user_agent: str) -> Tuple[int, str, Dict[str, bool]]:
    """Assess risk level for login attempt"""
    return adaptive_auth.assess_login_risk(user_id, ip_address, user_agent)


def get_auth_requirements(risk_score: int, risk_level: str) -> Dict[str, bool]:
    """Get authentication requirements based on risk"""
    return adaptive_auth.determine_auth_requirements(risk_score, risk_level)


def record_login(user_id: int, ip_address: str, user_agent: str, success: bool):
    """Record login attempt"""
    adaptive_auth.record_login_attempt(user_id, ip_address, user_agent, success)


def get_trust_score(user_id: int) -> int:
    """Get user's trust score"""
    return adaptive_auth.get_trust_score(user_id)
