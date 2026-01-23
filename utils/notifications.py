# utils/notifications.py
import requests
import smtplib
from email.mime.text import MIMEText
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# --- КОНФИГ ---
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')
EMAIL_TO = os.getenv('EMAIL_TO')

logging.basicConfig(level=logging.INFO)


def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logging.warning("Telegram: токен/чат не настроены")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'HTML'}
    try:
        response = requests.post(url, data=payload, timeout=10)
        if response.status_code == 200 and response.json().get('ok'):
            logging.info("Telegram: отправлено")
            return True
        else:
            logging.error(f"Telegram error {response.status_code}: {response.text}")
            return False
    except Exception as e:
        logging.error(f"Telegram exception: {e}")
        return False


def send_email(subject, body):
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, EMAIL_TO]):
        return
    msg = MIMEText(body, 'html')
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logging.info("Email: отправлено")
    except Exception as e:
        logging.error(f"Email error: {e}")


def notify_new_alert(alert_type, probability, source_ip=None):
    ip = f" (IP: {source_ip})" if source_ip else ""
    msg = f"<b>УГРОЗА!</b>\nТип: <code>{alert_type}</code>\nВероятность: <b>{probability:.1%}</b>{ip}"

    send_telegram(msg)
    # send_email("PreVisor: Новая угроза", msg)