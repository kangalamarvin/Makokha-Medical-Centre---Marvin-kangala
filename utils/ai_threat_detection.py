"""
AI-Powered Threat Detection System
Uses pattern recognition and behavioral analysis to detect sophisticated threats.

Features:
- Anomaly detection in user behavior
- Pattern-based threat identification
- Real-time threat scoring
- Behavioral profiling
- Attack pattern recognition
- Automated threat response
- Learning from security events
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
import json
import hashlib


class BehavioralProfile:
    """User behavioral profile for anomaly detection"""
    
    def  __init__(self, user_id: int):
        self.user_id = user_id
        self.typical_actions: Set[str] = set()
        self.access_patterns: Dict[str, int] = {}
        self.request_frequency: Dict[int, int] = {}  # hour -> count
        self.typical_endpoints: Set[str] = set()
        self.data_access_volume: List[int] = []
        self.failed_action_count = 0
        self.created_at = datetime.utcnow()
        self.last_updated = datetime.utcnow()
    
    def record_action(self, action: str, endpoint: str, hour: int, data_size: int = 0):
        """Record user action"""
        self.typical_actions.add(action)
        self.access_patterns[endpoint] = self.access_patterns.get(endpoint, 0) + 1
        self.request_frequency[hour] = self.request_frequency.get(hour, 0) + 1
        self.typical_endpoints.add(endpoint)
        if data_size > 0:
            self.data_access_volume.append(data_size)
        self.last_updated = datetime.utcnow()
    
    def is_typical_action(self, action: str) -> bool:
        """Check if action is typical for user"""
        return action in self.typical_actions
    
    def is_typical_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint access is typical"""
        return endpoint in self.typical_endpoints
    
    def is_typical_hour(self, hour: int) -> bool:
        """Check if hour is typical for user activity"""
        if not self.request_frequency:
            return True
        
        # Get average and check if hour has substantial activity
        avg_requests = sum(self.request_frequency.values()) / len(self.request_frequency)
        return self.request_frequency.get(hour, 0) >= (avg_requests * 0.3)
    
    def get_typical_data_volume(self) -> float:
        """Get average data access volume"""
        if not self.data_access_volume:
            return 0
        return sum(self.data_access_volume) / len(self.data_access_volume)
    
    def is_unusual_data_volume(self, volume: int) -> bool:
        """Check if data volume is unusually high"""
        typical_volume = self.get_typical_data_volume()
        if typical_volume == 0:
            return False
        
        # Flag if 5x typical volume
        return volume > (typical_volume * 5)


class ThreatPatterns:
    """Known attack patterns and signatures"""
    
    # Suspicious patterns in URLs/endpoints
    SUSPICIOUS_PATTERNS = [
        r'\.\./',  # Path traversal
        r'%2e%2e',  # Encoded path traversal
        r'<script',  # XSS attempt
        r'union.*select',  # SQL injection
        r'exec\s*\(',  # Code execution
        r'eval\s*\(',  # Code evaluation
        r';.*wget|curl',  # Command injection
        r'passwd|shadow',  # System file access
    ]
    
    # Suspicious action sequences
    ATTACK_SEQUENCES = [
        ['login_fail', 'login_fail', 'login_fail', 'login_success'],  # Brute force
        ['enumerate_users', 'enumerate_users', 'login_attempt'],  # User enumeration
        ['access_admin', 'access_admin', 'access_admin'],  # Privilege escalation attempt
        ['download', 'download', 'download', 'download'],  # Data exfiltration
    ]
    
    @classmethod
    def check_suspicious_pattern(cls, text: str) -> Tuple[bool, Optional[str]]:
        """Check if text contains suspicious patterns"""
        for pattern in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True, pattern
        return False, None
    
    @classmethod
    def check_attack_sequence(cls, recent_actions: List[str]) -> Tuple[bool, Optional[str]]:
        """Check if action sequence matches known attack pattern"""
        for attack_seq in cls.ATTACK_SEQUENCES:
            if len(recent_actions) >= len(attack_seq):
                # Check if recent actions match attack sequence
                if recent_actions[-len(attack_seq):] == attack_seq:
                    return True, '->'.join(attack_seq)
        return False, None


class AnomalyDetector:
    """Detect anomalies in user behavior"""
    
    def __init__(self):
        self.profiles: Dict[int, BehavioralProfile] = {}
        self.anomaly_threshold = 0.7  # 70% anomaly score triggers alert
    
    def get_or_create_profile(self, user_id: int) -> BehavioralProfile:
        """Get or create behavioral profile for user"""
        if user_id not in self.profiles:
            self.profiles[user_id] = BehavioralProfile(user_id)
        return self.profiles[user_id]
    
    def detect_anomalies(
        self,
        user_id: int,
        action: str,
        endpoint: str,
        hour: int,
        data_size: int = 0
    ) -> Tuple[float, List[str]]:
        """
        Detect anomalies in user behavior.
        
        Args:
            user_id: User ID
            action: Action being performed
            endpoint: Endpoint being accessed
            hour: Hour of day (0-23)
            data_size: Size of data accessed
            
        Returns:
            (anomaly_score, anomalies_detected)
        """
        profile = self.get_or_create_profile(user_id)
        anomalies = []
        anomaly_score = 0.0
        
        # Check if action is typical
        if not profile.is_typical_action(action):
            anomalies.append('unusual_action')
            anomaly_score += 0.2
        
        # Check if endpoint is typical
        if not profile.is_typical_endpoint(endpoint):
            anomalies.append('unusual_endpoint')
            anomaly_score += 0.15
        
        # Check if hour is typical
        if not profile.is_typical_hour(hour):
            anomalies.append('unusual_time')
            anomaly_score += 0.15
        
        # Check data volume
        if data_size > 0 and profile.is_unusual_data_volume(data_size):
            anomalies.append('unusual_data_volume')
            anomaly_score += 0.3
        
        # Check for suspicious patterns
        is_suspicious, pattern = ThreatPatterns.check_suspicious_pattern(endpoint)
        if is_suspicious:
            anomalies.append(f'suspicious_pattern:{pattern}')
            anomaly_score += 0.4
        
        # Cap anomaly score at 1.0
        anomaly_score = min(anomaly_score, 1.0)
        
        return anomaly_score, anomalies


class ThreatIntelligence:
    """Maintain threat intelligence database"""
    
    def __init__(self):
        self.known_threats: Dict[str, dict] = {}
        self.blocked_ips: Set[str] = set()
        self.malicious_patterns: List[str] = []
        self.threat_feeds: List[dict] = []
    
    def add_threat(self, threat_id: str, threat_data: dict):
        """Add threat to database"""
        self.known_threats[threat_id] = {
            **threat_data,
            'added_at': datetime.utcnow(),
            'severity': threat_data.get('severity', 'medium')
        }
    
    def is_known_threat(self, threat_signature: str) -> Tuple[bool, Optional[dict]]:
        """Check if threat signature is known"""
        threat_hash = hashlib.sha256(threat_signature.encode()).hexdigest()
        if threat_hash in self.known_threats:
            return True, self.known_threats[threat_hash]
        return False, None
    
    def add_blocked_ip(self, ip: str, reason: str):
        """Add IP to block list"""
        self.blocked_ips.add(ip)
        self.add_threat(f'ip_{ip}', {
            'type': 'blocked_ip',
            'ip': ip,
            'reason': reason,
            'severity': 'high'
        })
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips


class AIThreatDetector:
    """AI-Powered Threat Detection System"""
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.threat_intelligence = ThreatIntelligence()
        self.recent_actions: Dict[int, List[str]] = defaultdict(list)
        self.threat_scores: Dict[int, float] = {}
        self.alerts: List[dict] = []
        
        # Configuration
        self.enabled = True
        self.auto_block_threshold = 0.9
        self.alert_threshold = 0.7
        self.action_history_size = 20
    
    def enable(self):
        """Enable AI threat detection"""
        self.enabled = True
    
    def disable(self):
        """Disable AI threat detection"""
        self.enabled = False
    
    def analyze_request(
        self,
        user_id: int,
        action: str,
        endpoint: str,
        ip_address: str,
        data_size: int = 0
    ) -> Tuple[float, List[str], bool]:
        """
        Analyze request for threats.
        
        Args:
            user_id: User making request
            action: Action being performed
            endpoint: Endpoint being accessed
            ip_address: Client IP
            data_size: Size of data in request
            
        Returns:
            (threat_score, threats_detected, should_block)
        """
        if not self.enabled:
            return 0.0, [], False
        
        threats_detected = []
        threat_score = 0.0
        
        # Check if IP is blocked
        if self.threat_intelligence.is_ip_blocked(ip_address):
            threats_detected.append('blocked_ip')
            threat_score = 1.0
            return threat_score, threats_detected, True
        
        # Detect anomalies
        current_hour = datetime.utcnow().hour
        anomaly_score, anomalies = self.anomaly_detector.detect_anomalies(
            user_id, action, endpoint, current_hour, data_size
        )
        
        if anomaly_score > 0:
            threats_detected.extend(anomalies)
            threat_score += anomaly_score * 0.6
        
        # Check action sequence
        self.recent_actions[user_id].append(action)
        if len(self.recent_actions[user_id]) > self.action_history_size:
            self.recent_actions[user_id] = self.recent_actions[user_id][-self.action_history_size:]
        
        is_attack_seq, seq_pattern = ThreatPatterns.check_attack_sequence(
            self.recent_actions[user_id]
        )
        
        if is_attack_seq:
            threats_detected.append(f'attack_sequence:{seq_pattern}')
            threat_score += 0.4
        
        # Check for suspicious patterns in endpoint
        is_suspicious, pattern = ThreatPatterns.check_suspicious_pattern(endpoint)
        if is_suspicious:
            threats_detected.append(f'suspicious_pattern:{pattern}')
            threat_score += 0.3
        
        # Cap threat score at 1.0
        threat_score = min(threat_score, 1.0)
        
        # Update user threat score (running average)
        if user_id in self.threat_scores:
            self.threat_scores[user_id] = (self.threat_scores[user_id] * 0.7) + (threat_score * 0.3)
        else:
            self.threat_scores[user_id] = threat_score
        
        # Determine if should block
        should_block = threat_score >= self.auto_block_threshold
        
        # Generate alert if needed
        if threat_score >= self.alert_threshold:
            self.generate_alert(user_id, ip_address, threat_score, threats_detected)
        
        # Auto-block high-threat IPs
        if should_block:
            self.threat_intelligence.add_blocked_ip(
                ip_address,
                f"Auto-blocked: Threat score {threat_score:.2f}"
            )
        
        return threat_score, threats_detected, should_block

    def analyze_login_attempt(
        self,
        user_id: int,
        ip_address: str,
        user_agent: str,
        failed_attempts: int = 0,
        risk_factors: Optional[Dict[str, bool]] = None,
    ) -> float:
        """Analyze a login attempt and return a single threat score.

        This method exists to support the Flask login flow, which expects a
        numeric threat score (0.0 - 1.0).
        """
        if not self.enabled:
            return 0.0

        # Baseline: treat login as a request-like event.
        base_score, _, _ = self.analyze_request(
            user_id=user_id,
            action='login_attempt' if failed_attempts <= 0 else 'login_fail',
            endpoint='/auth/login',
            ip_address=ip_address,
            data_size=0,
        )

        score = float(base_score or 0.0)

        # Factor in repeated failures (brute-force signal)
        try:
            fa = int(failed_attempts or 0)
        except Exception:
            fa = 0
        if fa >= 3:
            score += 0.25
        elif fa == 2:
            score += 0.10
        elif fa == 1:
            score += 0.05

        # Factor in adaptive-auth risk signals (if provided)
        rf = risk_factors or {}
        try:
            if rf.get('unknown_device'):
                score += 0.10
            if rf.get('unusual_location'):
                score += 0.10
            if rf.get('unusual_time'):
                score += 0.05
            if rf.get('rapid_location_change'):
                score += 0.15
            if rf.get('suspicious_ip'):
                score += 0.20
            if rf.get('failed_attempts'):
                score += 0.10
        except Exception:
            # Never break login flow due to scoring issues
            pass

        # Incorporate user agent as a weak signal (very short/empty UAs are suspicious)
        try:
            ua = (user_agent or '').strip()
            if len(ua) < 12:
                score += 0.05
        except Exception:
            pass

        return min(max(score, 0.0), 1.0)
    
    def generate_alert(self, user_id: int, ip_address: str, threat_score: float, threats: List[str]):
        """Generate security alert"""
        alert = {
            'timestamp': datetime.utcnow(),
            'user_id': user_id,
            'ip_address': ip_address,
            'threat_score': threat_score,
            'threats_detected': threats,
            'severity': 'critical' if threat_score >= 0.9 else 'high' if threat_score >= 0.7 else 'medium'
        }
        
        self.alerts.append(alert)
        
        # Keep only last 1000 alerts
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
    
    def record_normal_activity(self, user_id: int, action: str, endpoint: str, data_size: int = 0):
        """Record normal activity to improve behavioral profile"""
        profile = self.anomaly_detector.get_or_create_profile(user_id)
        current_hour = datetime.utcnow().hour
        profile.record_action(action, endpoint, current_hour, data_size)
    
    def get_user_threat_score(self, user_id: int) -> float:
        """Get current threat score for user"""
        return self.threat_scores.get(user_id, 0.0)
    
    def get_recent_alerts(self, limit: int = 100) -> List[dict]:
        """Get recent security alerts"""
        return self.alerts[-limit:]
    
    def clear_user_history(self, user_id: int):
        """Clear user's activity history (use after investigation)"""
        if user_id in self.recent_actions:
            del self.recent_actions[user_id]
        if user_id in self.threat_scores:
            self.threat_scores[user_id] = 0.0


# Global instance
ai_threat_detector = AIThreatDetector()


# Utility functions
def analyze_threat(
    user_id: int,
    action: str,
    endpoint: str,
    ip_address: str,
    data_size: int = 0
) -> Tuple[float, List[str], bool]:
    """Analyze request for threats"""
    return ai_threat_detector.analyze_request(user_id, action, endpoint, ip_address, data_size)


def record_normal_activity(user_id: int, action: str, endpoint: str, data_size: int = 0):
    """Record normal user activity"""
    ai_threat_detector.record_normal_activity(user_id, action, endpoint, data_size)


def get_threat_score(user_id: int) -> float:
    """Get user's current threat score"""
    return ai_threat_detector.get_user_threat_score(user_id)


def get_security_alerts(limit: int = 100) -> List[dict]:
    """Get recent security alerts"""
    return ai_threat_detector.get_recent_alerts(limit)
