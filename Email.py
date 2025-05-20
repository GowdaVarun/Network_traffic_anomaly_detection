import json
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import os
import logging
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
APP_PASSWORD = os.getenv("APP_PASSWORD")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

NETWORK_FILE_PATH = "SCAM.json"
EMAIL_FILE_PATH = "email.json"

# Supported languages for notification
LANGUAGES = {
    "en": "English",
    "kn": "Kannada",
    "hi": "Hindi"
}

# Alert type descriptions for the model prompt
THREAT_TYPE_DESCRIPTIONS = {
    "1": {
        "en": "Port Scanning attempts",
        "kn": "ಪೋರ್ಟ್ ಸ್ಕ್ಯಾನಿಂಗ್ ಪ್ರಯತ್ನಗಳು",
        "hi": "पोर्ट स्कैनिंग प्रयास"
    },
    "2": {
        "en": "Denial of Service (DoS) attacks",
        "kn": "DoS ದಾಳಿಗಳು",
        "hi": "डिनायल ऑफ़ सर्विस (DoS) हमले"
    },
    "3": {
        "en": "Brute Force login attempts",
        "kn": "ಬ್ರುಟ್ ಫೋರ್ಸ್ ಲಾಗಿನ್ ಪ್ರಯತ್ನಗಳು",
        "hi": "ब्रूट फोर्स लॉगिन प्रयास"
    }
}

def load_emails():
    """Load recipient email addresses from JSON file"""
    try:
        with open(EMAIL_FILE_PATH, "r") as f:
            return json.load(f).get("emails", [])
    except Exception as e:
        logging.error(f"Error loading emails: {e}")
        return []

def get_admin_info():
    """Get admin info for personalization (stub - expand based on your data structure)"""
    # You can adapt this function if you have admin details in a file or environment variable.
    return {
        "name": os.getenv("ADMIN_NAME", "Admin")
    }

def generate_personalized_message(anomaly_type, count, lang, groq_api_key, context=None):
    """
    Generate a personalized, multilingual notification using Groq API.
    """
    admin = get_admin_info()
    threat_desc = THREAT_TYPE_DESCRIPTIONS.get(str(anomaly_type), {}).get(lang, "")
    base_prompt = (
        f"Write a concise, urgent, admin-level notification in {LANGUAGES[lang]} about a network security event. "
        f"The event is: {threat_desc}, occurred {count} time(s). "
        f"Personalize to admin {admin['name']}. "
        "Be clear, direct, and use notification tone. Avoid technical jargon beyond necessary context."
    )
    # Optionally, add more context about the anomaly
    if context:
        base_prompt += f" Details: {context}"

    # Groq API (OpenAI compatible)
    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json"
    }
    data = {
    "model": "llama3-8b-8192",  # Updated model
    "messages": [
        {"role": "system", "content": "You are a multilingual, security-focused alert assistant."},
        {"role": "user", "content": base_prompt}
    ],
    "temperature": 0.5,
    "max_tokens": 120
}

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=data, timeout=10)
        response.raise_for_status()
        result = response.json()
        return result['choices'][0]['message']['content'].strip()
    except Exception as e:
        logging.error(f"GROQ API error: {e}")
        # Fallback to default template message
        return f"⚠️ {count} {threat_desc} detected. Please check your network."

def create_multilingual_personalized_body(anomalies):
    """Create a personalized, multilingual email body using Groq API for each detected anomaly."""
    body = ""
    for lang in LANGUAGES.keys():
        lang_section = f"📘 {LANGUAGES[lang]}:\n"
        for key, count in anomalies.items():
            msg = generate_personalized_message(key, count, lang, GROQ_API_KEY)
            lang_section += f"{msg}\n"
        body += lang_section + "\n"
    return body.strip()

def send_email(recipient, subject, body):
    """Send an email with the given subject and body to the recipient"""
    msg = MIMEMultipart()
    msg["From"] = f"Python Alert System <{SENDER_EMAIL}>"
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient, msg.as_string())
        logging.info(f"Email sent to {recipient}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {recipient}: {e}")
        return False

def monitor_and_alert(poll_interval=10, cooldown_minutes=5):
    """Continuously monitor network traffic data and send alerts when anomalies are detected"""
    last_sent_time = None
    logging.info("Monitoring started... Press Ctrl+C to stop.")

    while True:
        try:
            with open(NETWORK_FILE_PATH, "r") as f:
                data = json.load(f)
        except Exception as e:
            logging.error(f"Could not read network data: {e}")
            time.sleep(poll_interval)
            continue

        summary = data.get("anomaly_summary", {})
        total_anomalies = summary.get("total_anomalies", 0)
        anomalies = summary.get("anomalies_by_type", {})
        now = datetime.now()

        if total_anomalies > 0 and anomalies:
            if last_sent_time is None or (now - last_sent_time) > timedelta(minutes=cooldown_minutes):
                logging.warning(f"{total_anomalies} anomalies detected. Sending alert...")

                # Compose personalized, multilingual alert
                alert_body = create_multilingual_personalized_body(anomalies)
                subject = "🚨 Network Threat Alert"

                for email in load_emails():
                    send_email(email, subject, alert_body)

                last_sent_time = now
                logging.info(f"Alert sent at {now.strftime('%H:%M:%S')}")
            else:
                logging.info(f"Alert recently sent, waiting cooldown. ({(now - last_sent_time).seconds}s elapsed)")
        else:
            logging.info(f"[{now.strftime('%H:%M:%S')}] No anomalies detected.")

        time.sleep(poll_interval)

def trigger_email():
    """Function to be called from external modules to trigger immediate email alerts"""
    try:
        with open(NETWORK_FILE_PATH, "r") as f:
            data = json.load(f)

        summary = data.get("anomaly_summary", {})
        total_anomalies = summary.get("total_anomalies", 0)
        anomalies = summary.get("anomalies_by_type", {})

        if total_anomalies > 0 and anomalies:
            logging.warning(f"External trigger: {total_anomalies} anomalies detected. Sending alert...")

            # Compose personalized, multilingual alert
            alert_body = create_multilingual_personalized_body(anomalies)
            subject = "🚨 Network Threat Alert (Triggered)"

            success = True
            for email in load_emails():
                if not send_email(email, subject, alert_body):
                    success = False

            return success
        else:
            logging.info("External trigger: No anomalies to report")
            return True
    except Exception as e:
        logging.error(f"External email trigger failed: {e}")
        return False

# Add logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Main execution
if __name__ == "__main__":
    monitor_and_alert()