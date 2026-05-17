"""Report generation in multiple formats (PDF, CSV, JSON)"""

import json
import csv
import datetime
import time
from io import BytesIO
from typing import Dict, List
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT


class ReportGenerator:
    """Generate reports in PDF, CSV, and JSON formats"""

    @staticmethod
    async def generate_pdf(artifact_value: str, artifact_type: str,
                           results: List[Dict], chart_buffer: BytesIO) -> BytesIO:
        """
        Generate PDF report

        Args:
            artifact_value: The artifact value
            artifact_type: Type of artifact
            results: List of analysis results
            chart_buffer: Chart image buffer

        Returns:
            BytesIO: PDF file buffer
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=72)

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2C3E50'),
            alignment=TA_CENTER,
            spaceAfter=30
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495E'),
            spaceAfter=12
        )

        story = []

        # Title
        story.append(Paragraph("OSINT Artifact Analysis Report", title_style))
        story.append(Spacer(1, 12))

        # Header info
        story.append(Paragraph(f"<b>Artifact:</b> {artifact_value}", styles['Normal']))
        story.append(Paragraph(f"<b>Type:</b> {artifact_type.upper()}", styles['Normal']))
        story.append(Paragraph(f"<b>Date:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))

        # Results section
        story.append(Paragraph("Analysis Results", heading_style))
        story.append(Spacer(1, 12))

        for result in results:
            if 'error' in result:
                continue

            service = result.get('service', 'Unknown')
            story.append(Paragraph(f"<b>{service}</b>", styles['Normal']))

            # Prepare table data
            data = []
            
            # Специальная обработка для DNS Records
            if service == "DNS Records":
                records = result.get('records', {})
                if records.get('A'):
                    data.append(['A Records', ', '.join(records['A'][:5])])
                if records.get('MX'):
                    mx_str = ', '.join([f"{mx['exchange']} (priority {mx['preference']})" for mx in records['MX'][:5]])
                    data.append(['MX Records', mx_str])
                if records.get('TXT'):
                    txt_str = '; '.join([txt[:60] + ('...' if len(txt) > 60 else '') for txt in records['TXT'][:3]])
                    data.append(['TXT Records', txt_str])
                if records.get('NS'):
                    data.append(['NS Records', ', '.join(records['NS'][:5])])
            else:
                # Обычная обработка для других сервисов
                for key, value in result.items():
                    if key != 'service' and not isinstance(value, (dict, list)):
                        key_name = key.replace('_', ' ').title()
                        value_str = str(value)[:100]
                        data.append([key_name, value_str])

            if data:
                table = Table(data, colWidths=[2*inch, 3.5*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(table)
                story.append(Spacer(1, 10))

        # Add simple text threat summary instead of chart
        threat_data = {
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0
        }
        
        for result in results:
            if result.get('service') == 'VirusTotal':
                threat_data['malicious'] = result.get('malicious', 0)
                threat_data['suspicious'] = result.get('suspicious', 0)
                threat_data['harmless'] = result.get('harmless', 0)
                threat_data['undetected'] = result.get('undetected', 0)
        
        total = sum(threat_data.values())
        if total > 0:
            story.append(Paragraph("Threat Summary", heading_style))
            story.append(Spacer(1, 12))
            
            threat_table_data = [
                ['Threat Type', 'Count', 'Percentage'],
                ['Malicious', str(threat_data['malicious']), f"{threat_data['malicious']/total*100:.1f}%"],
                ['Suspicious', str(threat_data['suspicious']), f"{threat_data['suspicious']/total*100:.1f}%"],
                ['Harmless', str(threat_data['harmless']), f"{threat_data['harmless']/total*100:.1f}%"],
                ['Undetected', str(threat_data['undetected']), f"{threat_data['undetected']/total*100:.1f}%"],
            ]
            
            threat_table = Table(threat_table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
            ]))
            story.append(threat_table)

        # Build PDF
        doc.build(story)
        buffer.seek(0)

        return buffer

    @staticmethod
    async def export_csv(results: List[Dict]) -> BytesIO:
        """
        Export results to CSV format

        Args:
            results: List of analysis results

        Returns:
            BytesIO: CSV file buffer
        """
        import csv
        
        buffer = BytesIO()
        
        # Collect all unique keys
        all_keys = set()
        for result in results:
            for key in result.keys():
                if key != 'service' and not isinstance(result[key], (dict, list)):
                    all_keys.add(key)
        
        all_keys = sorted(list(all_keys))
        
        # Build CSV as string first
        csv_lines = []
        
        # Header
        header = ['service'] + all_keys
        csv_lines.append(','.join(f'"{str(h)}"' for h in header))
        
        # Data rows
        for result in results:
            row = [result.get('service', 'Unknown')]
            for key in all_keys:
                value = result.get(key, 'N/A')
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                # Clean value for CSV
                value_str = str(value).replace('"', '""')
                row.append(value_str)
            csv_lines.append(','.join(f'"{str(r)}"' for r in row))
        
        # Write to buffer
        buffer.write('\n'.join(csv_lines).encode('utf-8'))
        buffer.seek(0)
        
        return buffer

    @staticmethod
    async def export_json(results: List[Dict]) -> BytesIO:
        """
        Export results to JSON format

        Args:
            results: List of analysis results

        Returns:
            BytesIO: JSON file buffer
        """
        buffer = BytesIO()
        
        # Convert to JSON string then to bytes
        json_str = json.dumps(results, indent=2, ensure_ascii=False, default=str)
        buffer.write(json_str.encode('utf-8'))
        buffer.seek(0)
        
        return buffer
