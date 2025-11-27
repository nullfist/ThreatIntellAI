from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from typing import List, Dict, Any, Optional
import os
from datetime import datetime

class PDFReportService:
    """Generate professional PDF reports for school incidents"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for school reports"""
        self.styles.add(ParagraphStyle(
            name='SchoolTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#2E86AB'),
            spaceAfter=12,
            alignment=1  # Center
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#A23B72'),
            spaceAfter=6,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.red,
            backColor=colors.HexColor('#FFE6E6'),
            borderPadding=5,
            borderColor=colors.red,
            borderWidth=1
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.orange,
            backColor=colors.HexColor('#FFF4E6'),
            borderPadding=5,
            borderColor=colors.orange,
            borderWidth=1
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.green,
            backColor=colors.HexColor('#E6FFE6'),
            borderPadding=5,
            borderColor=colors.green,
            borderWidth=1
        ))
    
    def generate_incident_report(self, report_data: Dict[str, Any], output_path: str) -> str:
        """Generate a comprehensive incident report PDF"""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Add header
        story.extend(self._create_header(report_data))
        
        # Add executive summary
        story.extend(self._create_executive_summary(report_data))
        
        # Add incident details
        story.extend(self._create_incident_details(report_data))
        
        # Add threat analysis
        story.extend(self._create_threat_analysis(report_data))
        
        # Add recommendations
        story.extend(self._create_recommendations(report_data))
        
        # Add footer
        story.extend(self._create_footer(report_data))
        
        doc.build(story)
        return output_path
    
    def _create_header(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create report header with school info"""
        elements = []
        
        # School name and title
        title_text = f"<b>{report_data['school_info']['school_name']}</b>"
        elements.append(Paragraph(title_text, self.styles['SchoolTitle']))
        
        # Report title
        report_title = f"<b>{report_data['title']}</b>"
        elements.append(Paragraph(report_title, self.styles['Heading1']))
        
        # Report metadata
        metadata_data = [
            ['Report ID:', report_data['report_id']],
            ['Generated:', report_data['generated_at']],
            ['Report Type:', report_data['report_type'].replace('_', ' ').title()],
        ]
        
        if report_data.get('student_info'):
            metadata_data.extend([
                ['Student:', report_data['student_info'].get('student_name', 'N/A')],
                ['Grade Level:', report_data['student_info'].get('grade_level', 'N/A')],
                ['Teacher:', report_data['student_info'].get('teacher_name', 'N/A')]
            ])
        
        metadata_table = Table(metadata_data, colWidths=[1.5*inch, 3*inch])
        metadata_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 9),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(metadata_table)
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_executive_summary(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        summary_text = f"""
        This security incident report documents potential cybersecurity threats detected within the school environment. 
        The analysis includes {len(report_data.get('ioc_findings', []))} threat indicators and 
        {len(report_data.get('log_findings', []))} security events from system logs.
        
        Overall Risk Level: <b>{report_data.get('overall_risk', 'Unknown').upper()}</b>
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _create_incident_details(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create incident details section"""
        elements = []
        
        elements.append(Paragraph("Incident Details", self.styles['SectionHeader']))
        
        # IOC Findings
        if report_data.get('ioc_findings'):
            elements.append(Paragraph("Threat Indicators Found:", self.styles['Heading3']))
            
            ioc_data = [['Type', 'Value', 'Risk Level', 'Threat Labels']]
            for finding in report_data['ioc_findings'][:5]:  # Show first 5
                ioc_data.append([
                    finding.get('ioc_type', 'N/A'),
                    finding.get('ioc', 'N/A')[:30] + '...' if len(finding.get('ioc', '')) > 30 else finding.get('ioc', 'N/A'),
                    finding.get('risk_level', 'N/A'),
                    ', '.join(finding.get('threat_labels', []))[:30] + '...'
                ])
            
            ioc_table = Table(ioc_data, colWidths=[1*inch, 1.5*inch, 1*inch, 2*inch])
            ioc_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 9),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E86AB')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F9F9F9')]),
            ]))
            
            elements.append(ioc_table)
            elements.append(Spacer(1, 0.1*inch))
        
        # Log Findings
        if report_data.get('log_findings'):
            elements.append(Paragraph("Security Events Detected:", self.styles['Heading3']))
            
            for finding in report_data['log_findings'][:3]:  # Show first 3
                risk_style = self._get_risk_style(finding.get('threat_severity', 'low'))
                event_text = f"<b>{finding.get('pattern_name', 'Unknown')}</b>: {finding.get('description', 'No description')}"
                elements.append(Paragraph(event_text, risk_style))
                elements.append(Spacer(1, 0.05*inch))
        
        elements.append(Spacer(1, 0.2*inch))
        return elements
    
    def _create_threat_analysis(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create threat analysis section with AI explanations"""
        elements = []
        
        elements.append(Paragraph("Threat Analysis", self.styles['SectionHeader']))
        
        if report_data.get('ai_explanation'):
            elements.append(Paragraph("AI Security Assessment:", self.styles['Heading3']))
            explanation_lines = report_data['ai_explanation'].split('\n')
            for line in explanation_lines:
                if line.strip():
                    elements.append(Paragraph(line.strip(), self.styles['Normal']))
                    elements.append(Spacer(1, 0.05*inch))
        
        elements.append(Spacer(1, 0.2*inch))
        return elements
    
    def _create_recommendations(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create recommendations section"""
        elements = []
        
        elements.append(Paragraph("Recommended Actions", self.styles['SectionHeader']))
        
        if report_data.get('recommended_actions'):
            elements.append(Paragraph("Immediate Steps for School Staff:", self.styles['Heading3']))
            
            for i, action in enumerate(report_data['recommended_actions'][:8], 1):  # Show first 8
                action_text = f"{i}. {action}"
                elements.append(Paragraph(action_text, self.styles['Normal']))
                elements.append(Spacer(1, 0.05*inch))
        
        # General security tips
        elements.append(Paragraph("General Security Best Practices:", self.styles['Heading3']))
        tips = [
            "Keep all software and systems updated with latest security patches",
            "Use strong, unique passwords for all school accounts",
            "Enable multi-factor authentication where available",
            "Regularly backup important school data",
            "Educate students and staff about phishing awareness",
            "Monitor network activity for unusual patterns"
        ]
        
        for tip in tips:
            elements.append(Paragraph(f"• {tip}", self.styles['Normal']))
            elements.append(Spacer(1, 0.03*inch))
        
        elements.append(Spacer(1, 0.2*inch))
        return elements
    
    def _create_footer(self, report_data: Dict[str, Any]) -> List[Any]:
        """Create report footer"""
        elements = []
        
        elements.append(Spacer(1, 0.3*inch))
        footer_text = """
        <i>This report was automatically generated by ThreatIntellAI - School Cybersecurity Platform.<br/>
        For questions or additional security support, contact your school IT administrator.<br/>
        Report generated on: {timestamp}</i>
        """.format(timestamp=report_data['generated_at'])
        
        elements.append(Paragraph(footer_text, self.styles['Italic']))
        return elements
    
    def _get_risk_style(self, risk_level: str) -> Any:
        """Get appropriate style based on risk level"""
        risk_styles = {
            'critical': 'RiskHigh',
            'high': 'RiskHigh', 
            'malicious': 'RiskHigh',
            'medium': 'RiskMedium',
            'suspicious': 'RiskMedium',
            'low': 'RiskLow',
            'safe': 'RiskLow'
        }
        return self.styles[risk_styles.get(risk_level.lower(), 'RiskLow')]