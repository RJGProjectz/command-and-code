#!/usr/bin/env python3
"""api-query.py - query a paginated JSON REST API and save the results.

A small, dependency-light client for security APIs. Handles bearer / ApiToken
authentication, retries with backoff on 429/5xx, and the three common pagination
styles. Writes JSON Lines (default) or CSV.

Pagination styles (--paging):
    odata    Microsoft Graph and other OData APIs: follows "@odata.nextLink", items in "value"
    cursor   SentinelOne Management API: follows pagination.nextCursor, items in "data"
    none     single request

The token is read from an environment variable - never pass secrets on the command line.

Examples:
    export GRAPH_TOKEN=...
    python api-query.py --url "https://graph.microsoft.com/v1.0/users?\\$select=id,userPrincipalName" \\
        --token-env GRAPH_TOKEN --paging odata --output users.jsonl

    export S1_TOKEN=...
    python api-query.py --url "https://CONSOLE/web/api/v2.1/agents?limit=200" \\
        --token-env S1_TOKEN --auth-scheme ApiToken --paging cursor --output agents.csv --format csv

Requires: requests (pip install requests).
Part of Command & Code.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from typing import Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("api-query")


def make_session(token: str, scheme: str) -> requests.Session:
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"Authorization": f"{scheme} {token}", "Accept": "application/json"})
    return session


def with_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    query.append((key, value))
    return urlunsplit(parts._replace(query=urlencode(query, safe="$,")))


def fetch(session: requests.Session, url: str, paging: str, timeout: int, max_pages: int) -> Iterator[dict]:
    pages = 0
    next_url: str | None = url
    while next_url and pages < max_pages:
        log.debug("GET %s", next_url)
        resp = session.get(next_url, timeout=timeout)
        if resp.status_code >= 400:
            log.error("HTTP %s: %s", resp.status_code, resp.text[:500])
            resp.raise_for_status()
        body = resp.json()
        pages += 1

        if paging == "odata":
            yield from body.get("value", [])
            next_url = body.get("@odata.nextLink")
        elif paging == "cursor":
            yield from body.get("data", [])
            cursor = (body.get("pagination") or {}).get("nextCursor")
            next_url = with_param(url, "cursor", cursor) if cursor else None
        else:
            if isinstance(body, list):
                yield from body
            else:
                yield body
            next_url = None
    if next_url:
        log.warning("stopped after --max-pages=%s; more results are available", max_pages)


def write_jsonl(items: Iterator[dict], path: str) -> int:
    count = 0
    with open(path, "w", encoding="utf-8") as out:
        for item in items:
            out.write(json.dumps(item, default=str) + "\n")
            count += 1
    return count


def write_csv(items: Iterator[dict], path: str) -> int:
    rows = list(items)
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with open(path, "w", newline="", encoding="utf-8-sig") as out:
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-env", required=True, help="name of the environment variable holding the token")
    parser.add_argument("--auth-scheme", default="Bearer", help="Bearer (default) or ApiToken for SentinelOne")
    parser.add_argument("--paging", choices=("odata", "cursor", "none"), default="none")
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-pages", type=int, default=1000)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    token = os.environ.get(args.token_env)
    if not token:
        log.error("environment variable %s is not set", args.token_env)
        return 2

    session = make_session(token, args.auth_scheme)
    items = fetch(session, args.url, args.paging, args.timeout, args.max_pages)
    try:
        count = write_csv(items, args.output) if args.format == "csv" else write_jsonl(items, args.output)
    except requests.RequestException as exc:
        log.error("request failed: %s", exc)
        return 1
    log.info("wrote %d items to %s", count, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
