"""Message handler for artifact analysis"""

import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from security.validators import InputValidator
from security.sanitizers import OutputSanitizer
from core.artifact_analyzer import ArtifactAnalyzer
from config import settings
from utils.rate_limiter import RateLimiter
rate_limiter = RateLimiter(max_requests=settings.security.max_requests_per_minute)

logger = logging.getLogger(__name__)

def format_results(artifact_type: str, artifact_value: str, results: list) -> str:
    """Format analysis results for display"""
    if not results:
        return f"🔍 *{artifact_type}:* `{artifact_value}`\n\n❌ No data found"

    output = f"🔍 *{artifact_type}:* `{artifact_value}`\n\n"

    for result in results:
        service = result.get("service", "Unknown")
        if "error" in result:
            continue

        output += f"📌 *{service}:*\n"

        if service == "AbuseIPDB":
            score = result.get("abuse_score", 0)
            emoji = "🔴" if score > 50 else "🟡" if score > 0 else "🟢"
            output += f"  {emoji} Score: {score}%\n"
            output += f"  📊 Reports: {result.get('total_reports', 0)}\n"
            output += f"  🌍 Country: {result.get('country', 'N/A')}\n"

#        elif service == "GreyNoise":
 #           classification = result.get("classification", "unknown")
  #          emoji = "🔴" if classification == "malicious" else "🟡" if classification == "suspicious" else "🟢"
   #         output += f"  {emoji} Classification: {classification}\n"
    #        output += f"  🎯 Noise: {'Yes' if result.get('noise') else 'No'}\n"
     #       output += f"  🏢 RIOT: {'Yes' if result.get('riot') else 'No'}\n"

        elif service == "VirusTotal":
            malicious = result.get("malicious", 0)
            emoji = "🔴" if malicious > 5 else "🟡" if malicious > 0 else "🟢"
            output += f"  {emoji} Malicious: {malicious}\n"
            output += f"  ⚠️ Suspicious: {result.get('suspicious', 0)}\n"
            output += f"  ✅ Harmless: {result.get('harmless', 0)}\n"

        elif service == "WHOIS":
            output += f"  📝 Registrar: {result.get('registrar', 'N/A')}\n"
            output += f"  📅 Created: {result.get('creation_date', 'N/A')}\n"
            output += f"  ⏰ Expires: {result.get('expiration_date', 'N/A')}\n"
            output += f"  🏢 Organization: {result.get('organization', 'N/A')}\n"

        elif service == "DNS Records":
            records = result.get('records', {})
            if records.get('A'):
                output += f"  🌐 A Records: {', '.join(records['A'][:3])}\n"
            if records.get('MX'):
                mx_str = ', '.join([f"{mx['exchange']}({mx['preference']})" for mx in records['MX'][:3]])
                output += f"  📧 MX Records: {mx_str}\n"
            if records.get('TXT'):
                output += f"  📝 TXT Records: {records['TXT'][0][:50]}...\n"

        elif service == "SSL/TLS":
            output += f"  🔒 Issuer: {result.get('issuer', 'N/A')}\n"
            output += f"  🏷️ Subject: {result.get('subject', 'N/A')}\n"
            output += f"  📅 Valid: {result.get('not_before', 'N/A')}\n"
            output += f"  📅 Until: {result.get('not_after', 'N/A')}\n"

        elif service == "Port Scanner":
            open_ports = result.get('open_ports', [])
            output += f"  🔓 Open ports: {len(open_ports)}\n"
            if open_ports:
                ports_str = ', '.join([f"{p['port']}({p['service']})" for p in open_ports[:5]])
                output += f"  📡 {ports_str}\n"

        elif service == "GeoLocation":
            output += f"  📍 Location: {result.get('city', 'N/A')}, {result.get('country', 'N/A')}\n"
            output += f"  🏢 ISP: {result.get('isp', 'N/A')}\n"
            if result.get('latitude'):
                output += f"  🗺️ Coordinates: {result['latitude']:.4f}, {result['longitude']:.4f}\n"

        elif service == "URLScan.io":
            output += f"  📊 Total scans: {result.get('total_scans', 0)}\n"
            output += f"  🚨 Malicious: {result.get('malicious_scans', 0)}\n"

        output += "\n"

    return OutputSanitizer.truncate(output, settings.security.max_message_length)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle incoming messages"""
    user_id = str(update.effective_user.id)
    message_text = update.message.text.strip()

    # Rate limiting
    if not rate_limiter.is_allowed(user_id):
        remaining = rate_limiter.get_remaining(user_id)
        await update.message.reply_text(
            f"⚠️ Rate limit exceeded. You have {remaining} requests left. Please wait."
        )
        return

    # Validate artifact
    artifact_type, artifact_value, error = InputValidator.validate_artifact(message_text)

    if artifact_type == "unknown":
        await update.message.reply_text(
            f"❌ {error}\n\nSend /help for supported formats."
        )
        return

    safe_value = OutputSanitizer.sanitize_markdown(artifact_value)

    processing_msg = await update.message.reply_text(
        f"🔍 Analyzing {artifact_type}: `{safe_value}`\nPlease wait..."
    )

    try:
        # Analyze
        analyzer = ArtifactAnalyzer()
        results = await analyzer.analyze(artifact_type, artifact_value)

        # Update stats
        context.user_data['total_analyzed'] = context.user_data.get('total_analyzed', 0) + 1

        # Format output
        output = format_results(artifact_type, safe_value, results)

        # Save for callbacks
        context.user_data['last_results'] = results
        context.user_data['last_artifact'] = {
            'type': artifact_type,
            'value': artifact_value
        }

        # Create buttons
        keyboard = [[
            InlineKeyboardButton("📊 PDF", callback_data=f"pdf_{artifact_type}_{artifact_value}"),
            InlineKeyboardButton("📈 Chart", callback_data=f"chart_{artifact_type}_{artifact_value}"),
            InlineKeyboardButton("💾 CSV", callback_data=f"csv_{artifact_type}_{artifact_value}"),
            InlineKeyboardButton("📄 JSON", callback_data=f"json_{artifact_type}_{artifact_value}")
        ]]

        await processing_msg.edit_text(
            output,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

        # Send map link if available
        for result in results:
            if result.get('service') == 'GeoLocation' and result.get('latitude'):
                lat, lon = result['latitude'], result['longitude']
                map_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=12"
                await update.message.reply_text(f"🗺️ Map: {map_url}")
                break

    except Exception as e:
        logger.error(f"Error analyzing artifact: {e}")
        await processing_msg.edit_text(
            "❌ Analysis failed. Please try again later."
        )
