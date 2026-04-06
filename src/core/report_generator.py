"""Report generation in multiple formats (PDF, CSV, JSON)"""

import json
import csv
import datetime
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

        # Add chart
        if chart_buffer:
            story.append(Paragraph("Threat Visualization", heading_style))
            story.append(Spacer(1, 12))
            img = Image(chart_buffer, width=5*inch, height=3*inch)
            story.append(img)

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
        buffer = BytesIO()

        # Collect all unique keys
        all_keys = set()
        for result in results:
            for key in result.keys():
                if key != 'service' and not isinstance(result[key], (dict, list)):
                    all_keys.add(key)

        # Write CSV
        writer = csv.writer(buffer)
        writer.writerow(['service'] + sorted(list(all_keys)))

        for result in results:
            row = [result.get('service', 'Unknown')]
            for key in sorted(all_keys):
                value = result.get(key, 'N/A')
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                row.append(str(value))
            writer.writerow(row)

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
        json.dump(results, buffer, indent=2, ensure_ascii=False, default=str)
        buffer.seek(0)
        return buffer
