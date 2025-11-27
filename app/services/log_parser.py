import re
from typing import List, Dict, Any, Tuple
from app.models.log_model import LogType

class LogParser:
    """Parse different types of log files and extract security events"""
    
    @staticmethod
    def parse_auth_log(lines: List[str]) -> Dict[str, Any]:
        """Parse Linux auth.log files"""
        events = {
            "failed_logins": [],
            "successful_logins": [],
            "unknown_users": [],
            "sudo_commands": [],
            "ssh_connections": []
        }
        
        for line in lines:
            # Failed password attempts
            if "Failed password" in line:
                events["failed_logins"].append(line)
                # Extract IP from failed login
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    events.setdefault("suspicious_ips", set()).add(ip_match.group(1))
            
            # Unknown users
            elif "invalid user" in line.lower():
                events["unknown_users"].append(line)
                user_match = re.search(r'invalid user (\w+)', line, re.IGNORECASE)
                if user_match:
                    events.setdefault("unknown_usernames", set()).add(user_match.group(1))
            
            # Successful logins
            elif "Accepted password" in line or "session opened" in line:
                events["successful_logins"].append(line)
            
            # Sudo commands
            elif "sudo:" in line and "COMMAND" in line:
                events["sudo_commands"].append(line)
            
            # SSH connections
            elif "Connection from" in line:
                events["ssh_connections"].append(line)
        
        return events
    
    @staticmethod
    def parse_iis_log(lines: List[str]) -> Dict[str, Any]:
        """Parse IIS web server logs"""
        events = {
            "status_codes": {},
            "suspicious_requests": [],
            "failed_requests": [],
            "bot_traffic": []
        }
        
        for line in lines:
            # Basic IIS log format parsing
            parts = line.split()
            if len(parts) >= 10:
                # Extract status code (typically 8th field)
                status_code = parts[8] if len(parts) > 8 else "unknown"
                ip_address = parts[0] if parts else "unknown"
                request_url = parts[4] if len(parts) > 4 else "unknown"
                
                # Track status codes
                events["status_codes"][status_code] = events["status_codes"].get(status_code, 0) + 1
                
                # Suspicious patterns
                if status_code in ['401', '403', '404', '500']:
                    events["failed_requests"].append({
                        "ip": ip_address,
                        "status": status_code,
                        "url": request_url,
                        "line": line
                    })
                
                # Bot-like patterns
                if any(bot in request_url.lower() for bot in ['bot', 'crawl', 'spider', 'scan']):
                    events["bot_traffic"].append(line)
                
                # SQL injection patterns
                if any(pattern in request_url.upper() for pattern in ['UNION', 'SELECT', 'INSERT', 'DROP', 'SCRIPT']):
                    events["suspicious_requests"].append({
                        "type": "sql_injection_attempt",
                        "ip": ip_address,
                        "url": request_url,
                        "line": line
                    })
        
        return events
    
    @staticmethod
    def parse_firewall_log(lines: List[str]) -> Dict[str, Any]:
        """Parse firewall logs (generic format)"""
        events = {
            "blocked_connections": [],
            "allowed_connections": [],
            "port_scans": [],
            "suspicious_ips": set()
        }
        
        for line in lines:
            line_lower = line.lower()
            
            # Blocked connections
            if any(term in line_lower for term in ['block', 'deny', 'drop']):
                events["blocked_connections"].append(line)
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    events["suspicious_ips"].add(ip_match.group(1))
            
            # Port scan detection
            elif any(term in line_lower for term in ['port scan', 'scan', 'probe']):
                events["port_scans"].append(line)
            
            # Allowed connections (for baseline)
            elif any(term in line_lower for term in ['allow', 'accept', 'permit']):
                events["allowed_connections"].append(line)
        
        return events
    
    @staticmethod
    def parse_windows_event_log(lines: List[str]) -> Dict[str, Any]:
        """Parse Windows Event Log format"""
        events = {
            "failed_logins": [],
            "account_lockouts": [],
            "privilege_escalation": [],
            "system_events": []
        }
        
        for line in lines:
            line_lower = line.lower()
            
            # Failed logins (Event ID 4625)
            if any(term in line_lower for term in ['logon failure', '4625', 'failed login']):
                events["failed_logins"].append(line)
            
            # Account lockouts (Event ID 4740)
            elif any(term in line_lower for term in ['account locked', '4740']):
                events["account_lockouts"].append(line)
            
            # Privilege escalation
            elif any(term in line_lower for term in ['privilege', 'elevation', 'sudo', 'runas']):
                events["privilege_escalation"].append(line)
            
            # System events
            elif any(term in line_lower for term in ['system', 'service', 'started', 'stopped']):
                events["system_events"].append(line)
        
        return events
    
    @staticmethod
    def detect_log_type(filename: str, content: List[str]) -> LogType:
        """Auto-detect log type based on filename and content"""
        filename_lower = filename.lower()
        
        if any(term in filename_lower for term in ['auth', 'secure', 'login']):
            return LogType.AUTH_LOG
        elif any(term in filename_lower for term in ['iis', 'w3svc']):
            return LogType.IIS
        elif any(term in filename_lower for term in ['firewall', 'iptables', 'ufw']):
            return LogType.FIREWALL
        elif any(term in filename_lower for term in ['windows', 'event', 'evtx']):
            return LogType.WINDOWS_EVENT
        elif any(term in filename_lower for term in ['apache', 'access', 'error_log']):
            return LogType.APACHE
        
        # Fallback: analyze content
        sample_content = ' '.join(content[:5]).lower()
        if 'failed password' in sample_content:
            return LogType.AUTH_LOG
        elif 'microsoft-iis' in sample_content:
            return LogType.IIS
        
        return LogType.AUTH_LOG  # Default fallback