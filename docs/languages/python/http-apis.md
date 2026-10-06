---
title: Python HTTP and APIs
platforms: [Microsoft 365, SentinelOne, Splunk]
languages: [Python]
tasks: [Automation, Incident Response]
category: APIs
tags: [requests, rest api, pagination, retries, oauth, timeout]
aliases: [python requests, api pagination python, retry requests, graph api python, timeout requests]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Python HTTP and APIs

Uses [`requests`](https://requests.readthedocs.io/) (`pip install requests`).

## GET with timeout and error checking

```python
import os
import requests

token = os.environ["API_TOKEN"]
resp = requests.get(
    "https://api.example.com/v1/items",
    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    params={"limit": 100, "status": "open"},
    timeout=30,
)
resp.raise_for_status()
items = resp.json()
```

!!! warning "Always set `timeout`"
    `requests` has **no default timeout** — a hung server hangs your script forever.

## POST JSON

```python
resp = requests.post(url, headers=headers, json={"name": "IR-2026-001", "tags": ["bec"]}, timeout=30)
```

`json=` serialises the body and sets `Content-Type: application/json`. Use `data=` for form-encoded bodies.

## Session with automatic retries

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def make_session(token: str) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,                       # 1s, 2s, 4s, ...
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        respect_retry_after_header=True,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"Authorization": f"Bearer {token}"})
    return session
```

Only retry `POST` when the endpoint is idempotent (search/query endpoints usually are; "create" endpoints usually are not).

## Pagination patterns

```python
def graph_get_all(session, url):
    """Microsoft Graph: follow @odata.nextLink."""
    while url:
        page = session.get(url, timeout=60).json()
        yield from page.get("value", [])
        url = page.get("@odata.nextLink")


def s1_get_all(session, base, path, params):
    """SentinelOne Management API: follow pagination.nextCursor."""
    params = dict(params)
    while True:
        page = session.get(f"{base}{path}", params=params, timeout=60).json()
        yield from page.get("data", [])
        cursor = page.get("pagination", {}).get("nextCursor")
        if not cursor:
            break
        params["cursor"] = cursor
```

SentinelOne uses the header `Authorization: ApiToken <token>` rather than `Bearer`.

## OAuth client credentials (Microsoft identity platform)

```python
def get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    resp = requests.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]
```

Microsoft's `msal` library handles token caching and certificate credentials and is preferable for long-running tools.

## TLS verification

Never ship `verify=False`. For an internal CA, point at its bundle: `requests.get(url, verify="/etc/ssl/certs/internal-ca.pem")` or set `REQUESTS_CA_BUNDLE`.

## Standard library only

When `requests` is not available on a host:

```python
import json
import urllib.request

req = urllib.request.Request("https://api.example.com/v1/items", headers={"Authorization": "Bearer TOKEN"})
with urllib.request.urlopen(req, timeout=30) as resp:
    data = json.load(resp)
```

## Related

- [`api-query.py` toolbox script](../../toolbox/python.md#api-querypy)
- [PowerShell REST APIs](../powershell/rest-apis.md)

## Sources

- [Requests: Quickstart (timeouts)](https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts)
- [urllib3 Retry](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.Retry)
- [Microsoft Graph paging](https://learn.microsoft.com/graph/paging)
