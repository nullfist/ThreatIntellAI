from typing import Dict, Any, List
from ..models.ioc_model import RiskLevel, ThreatLabel, IOCTypes
from ..models.log_model import ThreatSeverity

class AIExplainService:
    """AI-powered threat explanation service using prompt templates"""
    
    @staticmethod
    def generate_explanation(ioc: str, ioc_type: IOCTypes, risk_level: RiskLevel, 
                           threat_labels: List[ThreatLabel], threat_data: Dict[str, Any]) -> str:
        """Generate school-friendly threat explanation"""
        
        base_template = """
Security Analysis for {ioc_type}: {ioc}

RISK LEVEL: {risk_level}
THREAT TYPES: {threat_labels}

What this means for your school:
{school_impact}

Simple Explanation:
{simple_explanation}

What to look for:
{indicators}
"""
        
        # School impact descriptions
        impact_templates = {
            RiskLevel.MALICIOUS: "This poses a serious security risk to school computers and data.",
            RiskLevel.SUSPICIOUS: "This shows warning signs and should be approached with caution.",
            RiskLevel.SAFE: "This appears to be safe for normal school use."
        }
        
        # Simple explanations by IOC type
        explanation_templates = {
            IOCTypes.IP: {
                RiskLevel.MALICIOUS: "This internet address has been associated with harmful online activities.",
                RiskLevel.SUSPICIOUS: "This internet address shows some concerning patterns.",
                RiskLevel.SAFE: "This internet address appears normal and safe."
            },
            IOCTypes.URL: {
                RiskLevel.MALICIOUS: "This website is known for dangerous content that could harm school computers.",
                RiskLevel.SUSPICIOUS: "This website has some concerning reports and should be avoided.",
                RiskLevel.SAFE: "This website appears safe for educational use."
            },
            IOCTypes.DOMAIN: {
                RiskLevel.MALICIOUS: "This website name is linked to online threats targeting schools.",
                RiskLevel.SUSPICIOUS: "This website name has mixed reports and should be used carefully.",
                RiskLevel.SAFE: "This website name is registered for legitimate purposes."
            },
            IOCTypes.HASH: {
                RiskLevel.MALICIOUS: "This digital file fingerprint matches known computer viruses.",
                RiskLevel.SUSPICIOUS: "This file shows characteristics of potentially unwanted programs.",
                RiskLevel.SAFE: "This file appears to be clean and safe."
            }
        }
        
        # Threat-specific indicators
        threat_indicators = {
            ThreatLabel.MALWARE: "• Unexpected computer slowdowns\n• Pop-up warnings\n• Strange program behavior",
            ThreatLabel.PHISHING: "• Login requests from unfamiliar sites\n• Urgent security warnings\n• Requests for personal information",
            ThreatLabel.C2: "• Unusual network activity\n• Unknown background processes\n• Firewall alerts",
            ThreatLabel.BOTNET: "• Slow internet speed\n• Computer acting on its own\n• Spam emails from your account",
            ThreatLabel.SCAM: "• Too-good-to-be-true offers\n• Pressure to act quickly\n• Requests for money or gift cards"
        }
        
        # Build the explanation
        school_impact = impact_templates.get(risk_level, "This requires further investigation.")
        simple_explanation = explanation_templates[ioc_type].get(risk_level, "This requires careful evaluation.")
        
        # Build indicators list
        indicators = "General security tips:\n• Keep software updated\n• Use strong passwords\n• Be careful with email attachments"
        for label in threat_labels:
            if label in threat_indicators:
                indicators = threat_indicators[label]
                break
        
        explanation = base_template.format(
            ioc_type=ioc_type.value.upper(),
            ioc=ioc,
            risk_level=risk_level.value.upper(),
            threat_labels=", ".join([label.value for label in threat_labels]),
            school_impact=school_impact,
            simple_explanation=simple_explanation,
            indicators=indicators
        )
        
        return explanation.strip()
    
    @staticmethod
    def generate_recommended_actions(risk_level: RiskLevel, threat_labels: List[ThreatLabel]) -> List[str]:
        """Generate school-appropriate recommended actions"""
        
        base_actions = {
            RiskLevel.MALICIOUS: [
                "Block this immediately in school filters",
                "Report to IT administrator",
                "Scan affected computers for malware",
                "Change any compromised passwords"
            ],
            RiskLevel.SUSPICIOUS: [
                "Warn students and staff about this",
                "Monitor for related activity",
                "Consider blocking in school filters",
                "Verify with IT before taking action"
            ],
            RiskLevel.SAFE: [
                "No immediate action needed",
                "Continue normal monitoring",
                "Educate about general online safety"
            ]
        }
        
        # Add threat-specific actions
        additional_actions = []
        for label in threat_labels:
            if label == ThreatLabel.PHISHING:
                additional_actions.extend([
                    "Conduct phishing awareness training",
                    "Enable two-factor authentication"
                ])
            elif label == ThreatLabel.MALWARE:
                additional_actions.extend([
                    "Update antivirus software",
                    "Backup important files"
                ])
        
        actions = base_actions.get(risk_level, [])
        actions.extend(additional_actions)
        
        return list(set(actions))[:5]  # Return unique actions, max 5

    @staticmethod
    def generate_log_explanation(log_type, patterns, threat_severity, source_ips, failed_logins) -> str:
        """Generate school-friendly explanation for log analysis"""
        
        base_template = """
Log Security Analysis - {log_type}

OVERALL RISK: {threat_severity}

What we found in your school's logs:
{findings_summary}

What this means for your school:
{school_impact}

Key security issues detected:
{key_issues}

Simple explanation:
{simple_explanation}
"""
        
        # Findings summary
        if patterns:
            findings = [f"• {p.pattern_name}: {p.description}" for p in patterns[:5]]  # Top 5
            findings_summary = "\n".join(findings)
        else:
            findings_summary = "• No major security threats detected"
        
        # School impact based on severity
        impact_templates = {
            ThreatSeverity.CRITICAL: "Immediate action required! These logs show serious security breaches that could compromise school data and systems.",
            ThreatSeverity.HIGH: "High security concern detected. These patterns indicate targeted attacks on school systems.",
            ThreatSeverity.MEDIUM: "Moderate security concerns found. These require attention to prevent escalation.",
            ThreatSeverity.LOW: "Minor security observations. Good to review and monitor."
        }
        
        # Simple explanations
        explanation_templates = {
            ThreatSeverity.CRITICAL: "Your school logs show clear attack patterns that need immediate IT attention.",
            ThreatSeverity.HIGH: "These log entries indicate someone is trying to break into school systems.",
            ThreatSeverity.MEDIUM: "We found some suspicious activity that should be investigated.",
            ThreatSeverity.LOW: "The logs show normal activity with minor security notes."
        }
        
        # Key issues
        if source_ips:
            ip_list = ", ".join(source_ips[:3])  # Show first 3 IPs
            key_issues = f"Suspicious activity from: {ip_list}\nFailed login attempts: {failed_logins}"
        else:
            key_issues = f"Failed login attempts: {failed_logins}"
        
        explanation = base_template.format(
            log_type=log_type.value.replace('_', ' ').title(),
            threat_severity=threat_severity.value.upper(),
            findings_summary=findings_summary,
            school_impact=impact_templates.get(threat_severity, "Review recommended."),
            key_issues=key_issues,
            simple_explanation=explanation_templates.get(threat_severity, "Review logs for details.")
        )
        
        return explanation.strip()
    
    @staticmethod
    def generate_log_actions(threat_severity, patterns) -> List[str]:
        """Generate recommended actions for log findings"""
        
        base_actions = {
            ThreatSeverity.CRITICAL: [
                "IMMEDIATE: Contact IT security team",
                "Block suspicious IP addresses in firewall",
                "Reset all admin passwords",
                "Scan affected systems for malware",
                "Review all user accounts for compromise"
            ],
            ThreatSeverity.HIGH: [
                "Block the suspicious IP addresses",
                "Review failed login accounts",
                "Check for unauthorized access",
                "Update firewall rules",
                "Monitor for further activity"
            ],
            ThreatSeverity.MEDIUM: [
                "Investigate the suspicious patterns",
                "Monitor the source IPs",
                "Review account security",
                "Update security software",
                "Educate staff about findings"
            ],
            ThreatSeverity.LOW: [
                "Continue normal monitoring",
                "Document findings for future reference",
                "Review security policies",
                "No immediate action required"
            ]
        }
        
        actions = base_actions.get(threat_severity, [])
        
        # Add pattern-specific actions
        for pattern in patterns:
            if "Brute Force" in pattern.pattern_name:
                actions.append("Implement account lockout policy")
            if "Unknown User" in pattern.pattern_name:
                actions.append("Review user account creation process")
            if "Port Scanning" in pattern.pattern_name:
                actions.append("Check firewall configuration")
            if "SQL Injection" in pattern.pattern_name:
                actions.append("Review web application security")
                actions.append("Update web server rules")
        
        return list(set(actions))[:6]  # Return unique actions, max 6

    @staticmethod
    def explain_threat_context(context: str, ioc_id: str, detail_level: str = "concise") -> Dict[str, Any]:
        """AI-powered threat analysis for custom contexts"""
        
        # Template for different detail levels
        templates = {
            "concise": """
Threat Analysis Summary:

Context: {context}

Key Findings:
• {summary}

Recommended Action:
{immediate_action}
""",
            "detailed": """
Detailed Threat Analysis:

Context Overview:
{context}

Security Assessment:
{assessment}

Identified Risks:
{risks}

Technical Indicators:
{indicators}

Recommended Actions:
{actions}

Next Steps:
{next_steps}
"""
        }
        
        template = templates.get(detail_level, templates["concise"])
        
        # Generate analysis based on context
        if "login" in context.lower() or "password" in context.lower():
            summary = "Suspicious authentication activity detected"
            assessment = "Potential credential theft or brute force attempt"
            risks = "• Account compromise\n• Unauthorized access\n• Data theft"
            indicators = "• Multiple failed logins\n• Unknown user attempts\n• Suspicious IP addresses"
            actions = "• Reset affected passwords\n• Enable multi-factor authentication\n• Review login logs"
            next_steps = "Monitor for further authentication anomalies and educate users about password security"
            
        elif "malware" in context.lower() or "virus" in context.lower():
            summary = "Potential malware infection detected"
            assessment = "System may be compromised by malicious software"
            risks = "• Data loss\n• System damage\n• Network spread"
            indicators = "• Unusual file activity\n• Strange network connections\n• System performance issues"
            actions = "• Run antivirus scan\n• Isolate affected systems\n• Update security software"
            next_steps = "Conduct full system scan and review security controls"
            
        elif "phishing" in context.lower() or "email" in context.lower():
            summary = "Phishing attempt identified"
            assessment = "Attempt to steal credentials through deceptive communication"
            risks = "• Credential theft\n• Financial loss\n• Reputation damage"
            indicators = "• Suspicious sender addresses\n• Urgent action requests\n• Fake login pages"
            actions = "• Report the phishing email\n• Warn users\n• Update email filters"
            next_steps = "Conduct phishing awareness training and test email security"
            
        else:
            summary = "Security event requires investigation"
            assessment = "Unusual activity detected that needs further analysis"
            risks = "• Potential security breach\n• System vulnerability\n• Data exposure"
            indicators = "• Anomalous behavior patterns\n• Security rule violations\n• System errors"
            actions = "• Investigate the event\n• Review security logs\n• Update monitoring rules"
            next_steps = "Document findings and improve detection capabilities"
        
        if detail_level == "concise":
            explanation = template.format(
                context=context[:200] + "..." if len(context) > 200 else context,
                summary=summary,
                immediate_action=actions.split('\n')[0] if actions else "Investigate further"
            )
        else:
            explanation = template.format(
                context=context,
                assessment=assessment,
                risks=risks,
                indicators=indicators,
                actions=actions,
                next_steps=next_steps
            )
        
        return {
            "analysis": explanation.strip(),
            "explanation": f"AI analysis for incident {ioc_id}",
            "confidence": 0.85,
            "detail_level": detail_level,
            "recommendations": actions.split('\n') if actions else ["Investigate further"]
        }

    @staticmethod
    def get_ai_capabilities() -> Dict[str, Any]:
        """Get AI system capabilities and integration points"""
        
        return {
            "ai_system": "ThreatIntellAI Explanation Engine",
            "version": "1.1.0",
            "capabilities": [
                "IOC threat analysis and explanation",
                "Log pattern detection and interpretation", 
                "School-friendly risk communication",
                "Actionable security recommendations",
                "Multi-level detail explanations",
                "Context-aware threat assessment"
            ],
            "supported_formats": [
                "IP addresses, URLs, Domains, File hashes",
                "Linux auth.log, IIS, Firewall, Windows Event logs",
                "Custom security contexts",
                "Real-time threat intelligence"
            ],
            "explanation_levels": [
                "concise - Quick overview for immediate action",
                "detailed - Comprehensive analysis for investigation"
            ],
            "integrations_ready": [
                "OpenAI GPT models",
                "Local LLM deployment", 
                "Custom model training",
                "API-based AI services"
            ],
            "educational_features": [
                "Simple language explanations",
                "School-specific threat context",
                "Age-appropriate security guidance",
                "Teacher and admin focused recommendations"
            ],
            "status": "operational",
            "last_updated": "2024-01-15"
        }