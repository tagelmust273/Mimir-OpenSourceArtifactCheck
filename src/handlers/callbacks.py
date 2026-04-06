"""Callback handler for inline buttons"""

import logging
from telegram import Update, InputFile
from telegram.ext import ContextTypes

from core.visualization import Visualization
from core.report_generator import ReportGenerator
from security.sanitizers import OutputSanitizer

logger = logging.getLogger(__name__)


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle callback queries from inline buttons"""
    query = update.callback_query
    await query.answer()

    data = query.data.split('_')
    action = data[0]
    artifact_type = data[1]
    artifact_value = '_'.join(data[2:])

    results = context.user_data.get('last_results', [])

    if not results:
        await query.message.reply_text("❌ No results found. Please analyze again.")
        return

    try:
        if action == "pdf":
            await query.edit_message_text("📄 Generating PDF report...")

            # Prepare threat data
            threat_data = {
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0,
                'services': {}
            }

            for result in results:
                if result.get('service') == 'VirusTotal':
                    threat_data['malicious'] = result.get('malicious', 0)
                    threat_data['suspicious'] = result.get('suspicious', 0)
                    threat_data['harmless'] = result.get('harmless', 0)
                    threat_data['undetected'] = result.get('undetected', 0)
                elif result.get('service') == 'AbuseIPDB':
                    threat_data['services']['AbuseIPDB'] = result.get('abuse_score', 0)
                elif result.get('service') == 'GreyNoise':
                    classification = result.get('classification', 'unknown')
                    score = 75 if classification == 'malicious' else 25 if classification == 'suspicious' else 0
                    threat_data['services']['GreyNoise'] = score

            # Create chart
            chart_buffer = await Visualization.create_threat_chart(threat_data)

            # Generate PDF
            pdf_buffer = await ReportGenerator.generate_pdf(
                artifact_value, artifact_type, results, chart_buffer
            )

            await query.message.reply_document(
                document=InputFile(pdf_buffer, filename=f"report_{OutputSanitizer.sanitize_html(artifact_value)}.pdf"),
                caption=f"📊 Report for {OutputSanitizer.sanitize_html(artifact_value)}"
            )

        elif action == "csv":
            await query.edit_message_text("💾 Generating CSV export...")
            csv_buffer = await ReportGenerator.export_csv(results)

            await query.message.reply_document(
                document=InputFile(csv_buffer, filename=f"export_{OutputSanitizer.sanitize_html(artifact_value)}.csv"),
                caption=f"💾 CSV export for {OutputSanitizer.sanitize_html(artifact_value)}"
            )

        elif action == "json":
            await query.edit_message_text("📄 Generating JSON export...")
            json_buffer = await ReportGenerator.export_json(results)

            await query.message.reply_document(
                document=InputFile(json_buffer, filename=f"export_{OutputSanitizer.sanitize_html(artifact_value)}.json"),
                caption=f"📄 JSON export for {OutputSanitizer.sanitize_html(artifact_value)}"
            )

        elif action == "chart":
            await query.edit_message_text("📈 Generating threat chart...")

            # Prepare threat data
            threat_data = {
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0,
                'services': {}
            }

            for result in results:
                if result.get('service') == 'VirusTotal':
                    threat_data['malicious'] = result.get('malicious', 0)
                    threat_data['suspicious'] = result.get('suspicious', 0)
                    threat_data['harmless'] = result.get('harmless', 0)
                    threat_data['undetected'] = result.get('undetected', 0)
                elif result.get('service') == 'AbuseIPDB':
                    threat_data['services']['AbuseIPDB'] = result.get('abuse_score', 0)

            chart_buffer = await Visualization.create_threat_chart(threat_data)

            await query.message.reply_photo(
                photo=InputFile(chart_buffer, filename="threat_chart.png"),
                caption=f"📈 Threat chart for {OutputSanitizer.sanitize_html(artifact_value)}"
            )

        # Clean up
        await query.delete_message()

    except Exception as e:
        logger.error(f"Callback error: {e}")
        await query.message.reply_text(f"❌ Error: {str(e)}")
