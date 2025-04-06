import random
import smtplib
import textwrap
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

    return send_email(email, body)


def send_forgot_password_email(email, username, reset_token):
    subject = "freearpa - password reset request"
    body = textwrap.dedent(f"""\
        Subject: {subject}
        From: {const.EMAIL_FROM}
        To: {email}
        Message-ID: <{random.randint(1, 1000000)}@damcraft.de> 

        hey, {username}!

        you requested a password reset.
        open the link below to reset your password:
        https://freearpa.damcraft.de/reset-password/{reset_token}

        if you didn't request this, please ignore this email.

        best regards,
        dami
    """)

    return send_email(email, body)


def send_email(recipient, body):
    try:
        with smtplib.SMTP(const.SMTP_SERVER, const.SMTP_PORT) as server:
            server.starttls()
            server.login(const.SMTP_USERNAME, const.SMTP_PASSWORD)
            server.sendmail(const.EMAIL_FROM, recipient, body)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
