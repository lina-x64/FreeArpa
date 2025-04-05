import requests
import const

base_url = "https://api.cloudflare.com/client/v4"
headers = {
    'Authorization': f"Bearer {const.CLOUDFLARE_API_KEY}",
    'Content-Type': 'application/json'
}


def create_ns(subname, records):
    posts = []
    print(headers)
    for record in records:
        posts.append({
            'type': 'NS',
            'name': f"{subname}.{const.BASE_DOMAIN}",
            'content': record,
            'ttl': 3600
        })
    url = f"{base_url}/zones/{const.CLOUDFLARE_ZONE_ID}/dns_records/batch"
    response = requests.post(url, headers=headers, json={'posts': posts})
    return response


def update_ns(subname, records):
    # get existing records to delete
    name = f"{subname}.{const.BASE_DOMAIN}"
    existing = requests.get(
        f"{base_url}/zones/{const.CLOUDFLARE_ZONE_ID}/dns_records",
        headers=headers,
        params={'type': 'NS', 'name': name}
    )
    delete_ids = []
    if existing.ok:
        for r in existing.json().get('result', []):
            delete_ids.append({'id': r['id']})

    # prepare new records
    posts = []
    for record in records:
        posts.append({
            'type': 'NS',
            'name': name,
            'content': record,
            'ttl': 3600
        })

    url = f"{base_url}/zones/{const.CLOUDFLARE_ZONE_ID}/dns_records/batch"
    data = {'deletes': delete_ids, 'posts': posts}
    response = requests.post(url, headers=headers, json=data)
    return response
