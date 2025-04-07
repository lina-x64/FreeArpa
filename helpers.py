import base64
import hashlib
import hmac
import random
import threading

import requests
import const


def validate_turnstile(token, ip):
    response = requests.post(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        data={'secret': const.TURNSTILE_SECRET_KEY, 'response': token, 'remoteip': ip}
    )
    return response.json().get('success', False)


def generate_subname():
    nibbles = [random.choice('0123456789abcdef') for _ in range(5)]
    domain = ".".join(nibbles)
    key = generate_key(domain)
    return domain, key


def generate_key(subdomain):
    hmac_digest = hmac.new(const.HMAC_SECRET.encode("utf-8"), subdomain.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(hmac_digest).decode().rstrip('=')


def get_full_domain(subname):
    return f"{subname}.{const.BASE_DOMAIN}" if subname else const.BASE_DOMAIN


def get_subname(full_domain):
    if full_domain.endswith(f".{const.BASE_DOMAIN}"):
        subname = full_domain[:-len(f".{const.BASE_DOMAIN}")]
        return subname
    return None


def format_ns(ns):
    return ns.rstrip('.') + '.' if ns else None


user_locks = {}
global_lock = threading.Lock()


def get_user_lock(user_id):
    with global_lock:
        if user_id not in user_locks:
            user_locks[user_id] = threading.Lock()
        return user_locks[user_id]

