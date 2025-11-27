from typing import List, Dict, Any, Set
from app.models.log_model import ThreatSeverity, PatternDetection
from collections import Counter

class PatternDetector:
    """Detect suspicious patterns in log data"""
    
    @staticmethod
    def detect_brute_force(events: Dict[str, Any]) -> List[PatternDetection]:
        """Detect brute force attack patterns"""
        patterns = []
        
        # Check for multiple failed logins from same IP
        if "failed_logins" in events:
            ip_attempts = Counter()
            for event in events["failed_logins"]:
                ip_match = PatternDetector._extract_ip(event)
                if ip_match:
                    ip_attempts[ip_match] += 1
            
            # Identify IPs with high failure counts
            for ip, count in ip_attempts.items():
                if count >= 5:  # Threshold for brute force
                    severity = ThreatSeverity.HIGH if count > 10 else ThreatSeverity.MEDIUM
                    patterns.append(PatternDetection(
                        pattern_name="Brute Force Attack",
                        description=f"Multiple failed login attempts from IP {ip} ({count} attempts)",
                        severity=severity,
                        occurrences=count,
                        examples=[f"Failed logins from {ip}: {count} attempts"]
                    ))
        
        return patterns
    
    @staticmethod
    def detect_unknown_users(events: Dict[str, Any]) -> List[PatternDetection]:
        """Detect attempts with unknown usernames"""
        patterns = []
        
        if "unknown_users" in events and events["unknown_users"]:
            unknown_count = len(events["unknown_users"])
            usernames = list(events.get("unknown_usernames", set()))
            
            severity = ThreatSeverity.MEDIUM if unknown_count >= 3 else ThreatSeverity.LOW
            patterns.append(PatternDetection(
                pattern_name="Unknown User Attempts",
                description=f"Login attempts with {unknown_count} unknown usernames",
                severity=severity,
                occurrences=unknown_count,
                examples=[f"Unknown users attempted: {', '.join(usernames[:5])}"]  # Show first 5
            ))
        
        return patterns
    
    @staticmethod
    def detect_port_scans(events: Dict[str, Any]) -> List[PatternDetection]:
        """Detect port scanning activity"""
        patterns = []
        
        if "port_scans" in events and events["port_scans"]:
            scan_count = len(events["port_scans"])
            patterns.append(PatternDetection(
                pattern_name="Port Scanning",
                description=f"Detected {scan_count} port scan attempts",
                severity=ThreatSeverity.MEDIUM,
                occurrences=scan_count,
                examples=events["port_scans"][:3]  # Show first 3 examples
            ))
        
        return patterns
    
    @staticmethod
    def detect_sql_injection(events: Dict[str, Any]) -> List[PatternDetection]:
        """Detect SQL injection attempts"""
        patterns = []
        
        if "suspicious_requests" in events:
            sql_attempts = [req for req in events["suspicious_requests"] 
                          if req.get("type") == "sql_injection_attempt"]
            
            if sql_attempts:
                patterns.append(PatternDetection(
                    pattern_name="SQL Injection Attempts",
                    description=f"Detected {len(sql_attempts)} potential SQL injection attempts",
                    severity=ThreatSeverity.HIGH,
                    occurrences=len(sql_attempts),
                    examples=[f"SQL attempt from {attempt['ip']}: {attempt['url'][:100]}..." 
                             for attempt in sql_attempts[:3]]
                ))
        
        return patterns
    
    @staticmethod
    def detect_failed_requests(events: Dict[str, Any]) -> List[PatternDetection]:
        """Detect suspicious HTTP status codes"""
        patterns = []
        
        if "failed_requests" in events and events["failed_requests"]:
            status_counts = {}
            for req in events["failed_requests"]:
                status = req.get("status", "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1
            
            for status, count in status_counts.items():
                if count >= 10:  # High volume of errors
                    severity = ThreatSeverity.HIGH if status in ['401', '403'] else ThreatSeverity.MEDIUM
                    patterns.append(PatternDetection(
                        pattern_name=f"HTTP {status} Errors",
                        description=f"High volume of HTTP {status} errors ({count} occurrences)",
                        severity=severity,
                        occurrences=count,
                        examples=[f"Multiple {status} errors from various IPs"]
                    ))
        
        return patterns
    
    @staticmethod
    def analyze_all_patterns(events: Dict[str, Any]) -> List[PatternDetection]:
        """Run all pattern detection methods"""
        all_patterns = []
        
        all_patterns.extend(PatternDetector.detect_brute_force(events))
        all_patterns.extend(PatternDetector.detect_unknown_users(events))
        all_patterns.extend(PatternDetector.detect_port_scans(events))
        all_patterns.extend(PatternDetector.detect_sql_injection(events))
        all_patterns.extend(PatternDetector.detect_failed_requests(events))
        
        return all_patterns
    
    @staticmethod
    def _extract_ip(text: str) -> str:
        """Extract IP address from text"""
        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
        return ip_match.group(1) if ip_match else None