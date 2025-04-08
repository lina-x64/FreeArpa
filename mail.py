import random
import smtplib
from email.message import EmailMessage
import const


def send_welcome_email(email, username):
    subject = "welcome to freearpa.damcraft.de"
    body = f"""\
hey, {username}!

your account was successfully created.
if you have any questions, feel free to reach out!

best regards,
dami
"""
    return send_email(email, subject, body)


def send_forgot_password_email(email, username, reset_token):
    subject = "freearpa - password reset request"
    body = f"""\
hey, {username}!

you requested a password reset.
open the link below to reset your password:
https://freearpa.damcraft.de/reset-password/{reset_token}

if you didn't request this, please ignore this email.

best regards,
dami
"""
    return send_email(email, subject, body)


def send_email(recipient, subject, body):
    try:
        msg = EmailMessage()
        msg["From"] = const.EMAIL_FROM
        msg["To"] = recipient
        msg["Subject"] = subject
        msg["Message-ID"] = f"<{random.randint(1, 1_000_000)}@damcraft.de>"
        msg.set_content(body)

        with smtplib.SMTP(const.SMTP_SERVER, const.SMTP_PORT) as server:
            server.starttls()
            server.login(const.SMTP_USERNAME, const.SMTP_PASSWORD)
            server.send_message(msg)

        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
