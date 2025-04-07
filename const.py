import dotenv
import os

dotenv.load_dotenv()

DESEC_API_KEY = os.getenv("DESEC_API_KEY")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY")
HMAC_SECRET = os.getenv("HMAC_SECRET")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")

ZONE_PARTS = ["b", "f", "1", "5", "0", "7", "4", "0", "1", "0", "0", "2", "ip6", "arpa"]
BASE_DOMAIN = ".".join(ZONE_PARTS)
