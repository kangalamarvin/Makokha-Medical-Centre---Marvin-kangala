"""
Comprehensive Audit System
Enhanced auditing with detailed tracking and compliance reporting.

Features:
- Complete activity logging
- Change tracking (before/after)
- Security event logging
- Compliance reporting (HIPAA, GDPR)
- Audit trail integrity verification
- Real-time audit monitoring
- Tamper detection
- Automatic log rotation
- Export capabilities
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import os


class AuditEventType(Enum):
    """Types of auditable events"""
    # Authentication
    LOGIN = 'login'
    LOGOUT = 'logout'
    LOGIN_FAILED = 'login_failed'
    MFA_ENABLED = 'mfa_enabled'
    MFA_DISABLED = 'mfa_disabled'
    PASSWORD_CHANGED = 'password_changed'
    
    # Data Access
    VIEW_RECORD = 'view_record'
    CREATE_RECORD = 'create_record'
    UPDATE_RECORD = 'update_record'
    DELETE_RECORD = 'delete_record'
    EXPORT_DATA = 'export_data'
    
    # Security
    SECURITY_ALERT = 'security_alert'
    ACCESS_DENIED = 'access_denied'
    PERMISSION_CHANGED = 'permission_changed'
    SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    
    # System
    BACKUP_CREATED = 'backup_created'
    BACKUP_RESTORED = 'backup_restored'
    CONFIG_CHANGED = 'config_changed'
    
    # Medical
    PRESCRIPTION_CREATED = 'prescription_created'
    PRESCRIPTION_DISPENSED = 'prescription_dispensed'
    LAB_RESULT_VIEWED = 'lab_result_viewed'
    DIAGNOSIS_ADDED = 'diagnosis_added'


class AuditSeverity(Enum):
    """Severity levels for audit events"""
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


class AuditEntry:
    """Single audit log entry"""
    
    def __init__(
        self,
        event_type: AuditEventType,
        user_id: Optional[int],
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        old_values: Optional[Dict] = None,
        new_values: Optional[Dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[Dict] = None
    ):
        self.id = self._generate_id()
        self.timestamp = datetime.utcnow()
        self.event_type = event_type
        self.user_id = user_id
        self.action = action
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.old_values = old_values or {}
        self.new_values = new_values or {}
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.severity = severity
        self.metadata = metadata or {}
        self.checksum = self._calculate_checksum()
    
    def _generate_id(self) -> str:
        """Generate unique ID for audit entry"""
        return hashlib.sha256(
            f"{datetime.utcnow().isoformat()}{os.urandom(16).hex()}".encode()
        ).hexdigest()[:16]
    
    def _calculate_checksum(self) -> str:
        """Calculate checksum for tamper detection"""
        data = {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'old_values': self.old_values,
            'new_values': self.new_values,
        }
        
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def verify_checksum(self) -> bool:
        """Verify entry has not been tampered with"""
        expected_checksum = self._calculate_checksum()
        return self.checksum == expected_checksum
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'old_values': self.old_values,
            'new_values': self.new_values,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'severity': self.severity.value,
            'metadata': self.metadata,
            'checksum': self.checksum
        }


class ComplianceReport:
    """Generate compliance reports"""
    
    @staticmethod
    def generate_hipaa_report(
        audit_entries: List[AuditEntry],
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """
        Generate HIPAA compliance report.
        
        HIPAA requires:
        - Who accessed what information
        - When it was accessed
        - What was done with it
        """
        report = {
            'report_type': 'HIPAA Compliance',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_events': len(audit_entries),
            'access_events': [],
            'security_events': [],
            'data_modifications': [],
            'summary': {}
        }
        
        # Categorize events
        for entry in audit_entries:
            if entry.event_type in [AuditEventType.VIEW_RECORD, AuditEventType.EXPORT_DATA]:
                report['access_events'].append({
                    'timestamp': entry.timestamp.isoformat(),
                    'user_id': entry.user_id,
                    'resource': f"{entry.resource_type}:{entry.resource_id}",
                    'action': entry.action
                })
            
            if entry.event_type in [AuditEventType.SECURITY_ALERT, AuditEventType.ACCESS_DENIED]:
                report['security_events'].append({
                    'timestamp': entry.timestamp.isoformat(),
                    'user_id': entry.user_id,
                    'event': entry.action,
                    'severity': entry.severity.value
                })
            
            if entry.event_type in [AuditEventType.UPDATE_RECORD, AuditEventType.DELETE_RECORD]:
                report['data_modifications'].append({
                    'timestamp': entry.timestamp.isoformat(),
                    'user_id': entry.user_id,
                    'resource': f"{entry.resource_type}:{entry.resource_id}",
                    'action': entry.action,
                    'changes': {
                        'before': entry.old_values,
                        'after': entry.new_values
                    }
                })
        
        # Generate summary
        report['summary'] = {
            'total_accesses': len(report['access_events']),
            'total_security_events': len(report['security_events']),
            'total_modifications': len(report['data_modifications'])
        }
        
        return report
    
    @staticmethod
    def generate_gdpr_report(
        audit_entries: List[AuditEntry],
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """
        Generate GDPR compliance report.
        
        GDPR requires:
        - Right to access
        - Right to rectification
        - Right to erasure
        - Data processing activities
        """
        report = {
            'report_type': 'GDPR Compliance',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'total_events': len(audit_entries),
            'data_access': [],
            'data_modifications': [],
            'data_deletions': [],
            'summary': {}
        }
        
        for entry in audit_entries:
            if entry.event_type == AuditEventType.VIEW_RECORD:
                report['data_access'].append({
                    'timestamp': entry.timestamp.isoformat(),
                    'user_id': entry.user_id,
                    'resource': f"{entry.resource_type}:{entry.resource_id}"
                })
            
            if entry.event_type == AuditEventType.UPDATE_RECORD:
                report['data_modifications'].append({
                    'timestamp': entry.timestamp.isoformat(),
                    'user_id': entry.user_id,
                    'resource': f"{entry.resource_type}:{entry.resource_id}",
                    'changes': entry.new_values
                })
            
            if entry.event_type == AuditEventType.DELETE_RECORD:
                report['data_deletions'].append({
                    'timestamp': entry.timestamp.isoformat(),
                    'user_id': entry.user_id,
                    'resource': f"{entry.resource_type}:{entry.resource_id}"
                })
        
        report['summary'] = {
            'total_data_accesses': len(report['data_access']),
            'total_modifications': len(report['data_modifications']),
            'total_deletions': len(report['data_deletions'])
        }
        
        return report


class ComprehensiveAuditSystem:
    """Enhanced audit system with compliance support"""
    
    def __init__(self):
        self.entries: List[AuditEntry] = []
        self.max_entries = 100000  # Keep last 100k entries in memory
        
        # Configuration
        self.enabled = True
        self.auto_rotate = True
        self.rotation_size = 10000
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'events_by_type': {},
            'events_by_user': {},
            'security_alerts': 0
        }
    
    def enable(self):
        """Enable audit system"""
        self.enabled = True
    
    def disable(self):
        """Disable audit system"""
        self.enabled = False
    
    def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[int],
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        old_values: Optional[Dict] = None,
        new_values: Optional[Dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[Dict] = None
    ) -> AuditEntry:
        """Log an audit event"""
        if not self.enabled:
            return None
        
        entry = AuditEntry(
            event_type=event_type,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            old_values=old_values,
            new_values=new_values,
            ip_address=ip_address,
            user_agent=user_agent,
            severity=severity,
            metadata=metadata
        )
        
        self.entries.append(entry)
        
        # Update statistics
        self.stats['total_events'] += 1
        self.stats['events_by_type'][event_type.value] = \
            self.stats['events_by_type'].get(event_type.value, 0) + 1
        
        if user_id:
            self.stats['events_by_user'][user_id] = \
                self.stats['events_by_user'].get(user_id, 0) + 1
        
        if severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]:
            self.stats['security_alerts'] += 1
        
        # Auto-rotate if needed
        if self.auto_rotate and len(self.entries) > self.max_entries:
            self._rotate_logs()
        
        return entry
    
    def _rotate_logs(self):
        """Rotate log entries (keep most recent)"""
        # In production, archive old entries to database or file
        self.entries = self.entries[-self.rotation_size:]
    
    def query_events(
        self,
        user_id: Optional[int] = None,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[int] = None,
        severity: Optional[AuditSeverity] = None
    ) -> List[AuditEntry]:
        """Query audit events with filters"""
        results = self.entries.copy()
        
        if user_id is not None:
            results = [e for e in results if e.user_id == user_id]
        
        if event_type is not None:
            results = [e for e in results if e.event_type == event_type]
        
        if start_time is not None:
            results = [e for e in results if e.timestamp >= start_time]
        
        if end_time is not None:
            results = [e for e in results if e.timestamp <= end_time]
        
        if resource_type is not None:
            results = [e for e in results if e.resource_type == resource_type]
        
        if resource_id is not None:
            results = [e for e in results if e.resource_id == resource_id]
        
        if severity is not None:
            results = [e for e in results if e.severity == severity]
        
        return results
    
    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Verify audit trail integrity"""
        tampered_entries = []
        
        for entry in self.entries:
            if not entry.verify_checksum():
                tampered_entries.append(entry.id)
        
        is_intact = len(tampered_entries) == 0
        return is_intact, tampered_entries
    
    def generate_hipaa_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """Generate HIPAA compliance report"""
        entries = self.query_events(start_time=start_date, end_time=end_date)
        return ComplianceReport.generate_hipaa_report(entries, start_date, end_date)
    
    def generate_gdpr_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict:
        """Generate GDPR compliance report"""
        entries = self.query_events(start_time=start_date, end_time=end_date)
        return ComplianceReport.generate_gdpr_report(entries, start_date, end_date)
    
    def get_statistics(self) -> Dict:
        """Get audit system statistics"""
        return self.stats.copy()
    
    def export_to_json(self, filepath: str):
        """Export"""
        data = [entry.to_dict() for entry in self.entries]
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


# Global instance
comprehensive_audit = ComprehensiveAuditSystem()


# Utility functions
def log_audit_event(
    event_type: AuditEventType,
    user_id: Optional[int],
    action: str,
    **kwargs
) -> AuditEntry:
    """Log an audit event"""
    return comprehensive_audit.log_event(event_type, user_id, action, **kwargs)


def query_audit_events(**kwargs) -> List[AuditEntry]:
    """Query audit events"""
    return comprehensive_audit.query_events(**kwargs)


def verify_audit_integrity() -> Tuple[bool, List[str]]:
    """Verify audit trail integrity"""
    return comprehensive_audit.verify_integrity()


def get_audit_statistics() -> Dict:
    """Get audit statistics"""
    return comprehensive_audit.get_statistics()
