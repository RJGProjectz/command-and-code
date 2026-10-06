---
title: Python Logging and Automation
platforms: [Linux, Windows]
languages: [Python]
tasks: [Automation]
category: Automation
tags: [logging, argparse, cli, concurrency, threadpool, venv]
aliases: [python script template, argparse, logging to file python, run api calls in parallel, virtual environment]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Python Logging and Automation

## Script template

```python
#!/usr/bin/env python3
"""collect_example.py — one-line description.

Example:
    python collect_example.py --hosts hosts.txt --output results.csv -v
"""
from __future__ import annotations

import argparse
import logging
import sys

log = logging.getLogger("collect_example")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hosts", required=True, help="file with one host per line")
    parser.add_argument("--output", default="results.csv")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log.info("starting with %s", args.hosts)
    try:
        ...  # work
    except Exception:
        log.exception("unhandled error")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Pass values to logging as arguments (`log.info("x=%s", x)`) rather than f-strings — formatting is skipped when the level is disabled.

## Log to a rotating file

```python
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler("collector.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logging.getLogger().addHandler(handler)
```

## Many API calls in parallel

I/O-bound work (HTTP, SSH) parallelises well with threads:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def lookup(host: str) -> dict:
    return {"host": host, "status": "ok"}

hosts = ["ws01", "ws02", "ws03"]
results = []
with ThreadPoolExecutor(max_workers=10) as pool:
    futures = {pool.submit(lookup, h): h for h in hosts}
    for future in as_completed(futures):
        try:
            results.append(future.result())
        except Exception as exc:
            results.append({"host": futures[future], "error": str(exc)})
```

Keep `max_workers` below the API's rate limit.

## Virtual environments

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Related

- [`api-query.py`](../../toolbox/python.md#api-querypy)
- [Python HTTP and APIs](http-apis.md)

## Sources

- [logging HOWTO](https://docs.python.org/3/howto/logging.html)
- [argparse — Python docs](https://docs.python.org/3/library/argparse.html)
- [concurrent.futures — Python docs](https://docs.python.org/3/library/concurrent.futures.html)
