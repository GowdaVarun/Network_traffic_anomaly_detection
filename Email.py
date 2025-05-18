import json
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration constants
NETWORK_FILE_PATH = "SCAM.json"
EMAIL_FILE_PATH = "email.json"
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
APP_PASSWORD = os.getenv("APP_PASSWORD")

# Alert templates in multiple languages
alert_templates = {
    "1": {
        "en": "⚠️ Detected {count} Port Scanning attempts on your network.",
        "kn": "⚠️ ನಿಮ್ಮ ಜಾಲದಲ್ಲಿ {count} ಪೋರ್ಟ್ ಸ್ಕ್ಯಾನಿಂಗ್ ಪ್ರಯತ್ನಗಳು ಕಂಡುಬಂದಿವೆ.",
        "te": "⚠️ మీ నెట్‌వర్క్‌లో {count} పోర్ట్ స్కానింగ్ ప్రయత్నాలు గుర్తించబడ్డాయి."
    },
    "2": {
        "en": "🚨 Detected {count} potential Denial of Service (DoS) attacks.",
        "kn": "🚨 {count} ಸಾಧ್ಯವಿರುವ DoS ದಾಳಿಗಳನ್ನು ಪತ್ತೆಹಚ್ಚಲಾಗಿದೆ.",
        "te": "🚨 {count} DoS దాడులు గుర్తించబడ్డాయి."
    },
    "3": {
        "en": "🔐 Detected {count} Brute Force login attempts.",
        "kn": "🔐 {count} ಬ್ರುಟ್ ಫೋರ್ಸ್ ಲಾಗಿನ್ ಪ್ರಯತ್ನಗಳನ್ನು ಕಂಡುಹಿಡಿಯಲಾಗಿದೆ.",
        "te": "🔐 {count} బ్రూట్ ఫోర్స్ లాగిన్ ప్రయత్నాలు గుర్తించబడ్డాయి."
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

def create_multilingual_body(anomalies):
    """Create email body with alerts in multiple languages"""
    en_msgs, kn_msgs, te_msgs = [], [], []
    
    for key, count in anomalies.items():
        template = alert_templates.get(str(key))
        if template:
            en_msgs.append(template['en'].format(count=count))
            kn_msgs.append(template['kn'].format(count=count))
            te_msgs.append(template['te'].format(count=count))
    
    return (
        "📘 English:\n" + "\n".join(en_msgs) + "\n\n"
        "📗 ಕನ್ನಡ:\n" + "\n".join(kn_msgs) + "\n\n"
        "📕 తెలుగు:\n" + "\n".join(te_msgs)
    )

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
                
                # Compose alert with counts
                alert_body = create_multilingual_body(anomalies)
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
            
            # Compose alert with counts
            alert_body = create_multilingual_body(anomalies)
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
