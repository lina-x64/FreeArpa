import requests

import const

base_url = "https://desec.io/api/v1"
headers = {'Authorization': f'Token {const.DESEC_API_KEY}', 'Content-Type': 'application/json'}


def create_ns(subname, records):
    url = f"{base_url}/domains/{const.BASE_DOMAIN}/rrsets/"
    data = {'subname': subname, 'type': 'NS', 'ttl': 3600, 'records': records}
    response = requests.post(url, headers=headers, json=data)
    return response


def get_ns(subname):
    url = f"{base_url}/domains/{const.BASE_DOMAIN}/rrsets/{subname}/NS/"
    response = requests.get(url, headers=headers)
    if response.ok:
        return response.json().get('records', [])
    return []


def update_ns(subname, records):
    url = f"{base_url}/domains/{const.BASE_DOMAIN}/rrsets/{subname}/NS/"
    data = {'subname': subname, 'type': 'NS', 'ttl': 3600, 'records': records}
    response = requests.put(url, headers=headers, json=data)
    return response
