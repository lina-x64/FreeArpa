import random
import secrets
import smtplib
import textwrap
import time

import const


def send_welcome_email(email, username):
    subject = "welcome to freearpa.damcraft.de"
    body = textwrap.dedent(f"""\
        Subject: {subject}
        From: {const.EMAIL_FROM}
        To: {email}
        Message-ID: <{random.randint(1, 1000000)}@damcraft.de> 
        hey, {username}!
        your account was successfully created.
        if you have any questions, feel free to reach out!
        best regards,
        dami
    """)

    try:
        with smtplib.SMTP(const.SMTP_SERVER, const.SMTP_PORT) as server:
            server.starttls()
            server.login(const.SMTP_USERNAME, const.SMTP_PASSWORD)
            server.sendmail(const.EMAIL_FROM, email, body)
    except Exception as e:
        print(f"Failed to send email: {e}")


def send_forgot_password_email(email, username):
    token = secrets.token_urlsafe(32)
    tokens[token] = username, time.time() + 3600  # 1 hour expiration

    subject = "freearpa - password reset request"
    body = textwrap.dedent(f"""\
        Subject: {subject}
        From: {const.EMAIL_FROM}
        To: {email}
        Message-ID: <{random.randint(1, 1000000)}@damcraft.de> 
        hey, {username}!
        you requested a password reset.
        open the link below to reset your password:
        https://freearpa.damcraft.de/reset-password/{token}
        if you didn't request this, please ignore this email.
        best regards,
        dami
    """)
    try:
        with smtplib.SMTP(const.SMTP_SERVER, const.SMTP_PORT) as server:
            server.starttls()
            server.login(const.SMTP_USERNAME, const.SMTP_PASSWORD)
            server.sendmail(const.EMAIL_FROM, email, body)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def validate_token(token):
    if token in tokens:
        username, expiration = tokens[token]
        if time.time() < expiration:
            return username
        else:
            return None


def invalidate_token(token):
    if token in tokens:
        del tokens[token]


tokens = {}
