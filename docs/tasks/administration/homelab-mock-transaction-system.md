---
title: Administration — Homelab Mock Transaction System Roadmap
type: workflow
platforms:
  - Linux
languages:
  - Bash
  - Python
  - REST API
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-28
difficulty: advanced
tags:
  - mock
  - transactions
  - api
  - postgresql
  - redis
  - jwt
  - mtls
  - audit-log
  - testing
---

# Administration — Homelab Mock Transaction System Roadmap

> **Scope disclaimer — read first.**  
> This is a **mock system for learning purposes only**. It must never handle real financial data, connect to live payment processors, store actual card numbers or bank credentials, or be exposed to the public internet without authentication. All accounts, transaction IDs, and amounts in this guide are fabricated test data.

A blueprint for building a fully local, test-only payment/transaction system — useful for learning API design, database schema, inter-service mTLS, audit logging, and contract testing, without touching real money.

---

## 1. System Architecture

```
  Client (curl / test script)
          │
          │ HTTPS + JWT Bearer token
          ▼
  ┌─────────────────────┐
  │    API Gateway       │   (NGINX or Caddy)
  │  TLS termination     │
  │  JWT validation      │
  └────────┬────────────┘
           │ mTLS (client cert required)
           ▼
  ┌─────────────────────┐
  │  Transaction Service │   (Python/FastAPI or Go)
  │  Business logic      │
  │  Idempotency keys    │
  └────┬──────┬─────────┘
       │      │
       │      │  Publish events
       │      ▼
       │  ┌──────────────────┐
       │  │  Message Queue    │   (Redis Streams or RabbitMQ)
       │  │  async notify /   │
       │  │  retry on failure │
       │  └──────────────────┘
       │
       │ SQL (TLS)
       ▼
  ┌─────────────────────┐
  │     Ledger DB        │   (PostgreSQL)
  │  accounts            │
  │  transactions        │
  │  audit_log           │
  └─────────────────────┘
```

### Component responsibilities

| Component | Technology | Role |
|-----------|-----------|------|
| API Gateway | NGINX / Caddy | TLS termination, JWT signature check, rate limiting |
| Transaction Service | Python (FastAPI) | Business rules: balance check, debit/credit, idempotency |
| Message Queue | Redis Streams | Decouple event notification; retry on downstream failure |
| Ledger DB | PostgreSQL | Durable record of accounts and all transactions |

---

## 2. API Design

### Base URL

```
https://transactions.homelab.local/v1
```

### Endpoints

#### POST /v1/transactions — create a transaction

```http
POST /v1/transactions HTTP/1.1
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "idempotency_key": "inv-2026-0042",
  "from_account": "acc_001",
  "to_account":   "acc_002",
  "amount":       "50.00",
  "currency":     "USD",
  "description":  "Test transfer"
}
```

**Response 201**

```json
{
  "transaction_id": "txn_8f3a1b9c",
  "status":         "completed",
  "from_account":   "acc_001",
  "to_account":     "acc_002",
  "amount":         "50.00",
  "currency":       "USD",
  "created_at":     "2026-10-28T02:00:00Z"
}
```

**Response 409** — idempotency key already used (same request replayed)

```json
{
  "error": "duplicate_request",
  "original_transaction_id": "txn_8f3a1b9c"
}
```

#### GET /v1/transactions/{id} — retrieve a transaction

```http
GET /v1/transactions/txn_8f3a1b9c HTTP/1.1
Authorization: Bearer <jwt>
```

**Response 200**

```json
{
  "transaction_id": "txn_8f3a1b9c",
  "status":         "completed",
  "amount":         "50.00",
  "currency":       "USD",
  "created_at":     "2026-10-28T02:00:00Z",
  "refunded":       false
}
```

#### POST /v1/refunds — create a refund

```http
POST /v1/refunds HTTP/1.1
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "transaction_id": "txn_8f3a1b9c",
  "amount":         "50.00",
  "reason":         "test_refund"
}
```

**Response 201**

```json
{
  "refund_id":      "ref_1a2b3c4d",
  "transaction_id": "txn_8f3a1b9c",
  "status":         "completed",
  "amount":         "50.00",
  "created_at":     "2026-10-28T02:05:00Z"
}
```

**Response 422** — amount exceeds original transaction

```json
{
  "error": "refund_exceeds_original",
  "max_refundable": "50.00"
}
```

### HTTP status code conventions

| Code | Meaning in this API |
|------|-------------------|
| 201 | Resource created successfully |
| 400 | Malformed request (missing field, bad currency code) |
| 401 | Missing or invalid JWT |
| 403 | JWT valid but scope insufficient |
| 404 | Transaction/account not found |
| 409 | Idempotency conflict |
| 422 | Semantic error (insufficient balance, refund exceeds original) |
| 500 | Unexpected server error |

---

## 3. Database Schema

```sql
-- accounts: holds test balances, no real PII
CREATE TABLE accounts (
    account_id    TEXT        PRIMARY KEY,          -- acc_001, acc_002, ...
    display_name  TEXT        NOT NULL,
    balance       NUMERIC(18,2) NOT NULL DEFAULT 0,
    currency      CHAR(3)     NOT NULL DEFAULT 'USD',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- transactions: immutable ledger entries
CREATE TABLE transactions (
    transaction_id   TEXT        PRIMARY KEY,       -- txn_<random>
    idempotency_key  TEXT        UNIQUE NOT NULL,   -- client-supplied, for deduplication
    from_account     TEXT        REFERENCES accounts(account_id),
    to_account       TEXT        REFERENCES accounts(account_id),
    amount           NUMERIC(18,2) NOT NULL CHECK (amount > 0),
    currency         CHAR(3)     NOT NULL,
    status           TEXT        NOT NULL,          -- pending | completed | failed | refunded
    description      TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- refunds: linked back to the original transaction
CREATE TABLE refunds (
    refund_id        TEXT        PRIMARY KEY,
    transaction_id   TEXT        NOT NULL REFERENCES transactions(transaction_id),
    amount           NUMERIC(18,2) NOT NULL CHECK (amount > 0),
    reason           TEXT,
    status           TEXT        NOT NULL DEFAULT 'completed',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- audit_log: append-only record of every state change (ECS-aligned fields)
CREATE TABLE audit_log (
    log_id         BIGSERIAL   PRIMARY KEY,
    "@timestamp"   TIMESTAMPTZ NOT NULL DEFAULT now(),
    "event.action" TEXT        NOT NULL,            -- transaction.created | refund.created | ...
    "event.outcome" TEXT       NOT NULL,            -- success | failure
    "transaction.id" TEXT,
    "user.id"      TEXT,                            -- JWT subject claim
    "source.ip"    INET,
    detail         JSONB
);

-- Indexes
CREATE INDEX ON transactions(from_account);
CREATE INDEX ON transactions(to_account);
CREATE INDEX ON transactions(created_at DESC);
CREATE INDEX ON audit_log("@timestamp" DESC);
```

### Data access pattern

All balance mutations run inside a serialisable transaction to avoid double-spend:

```sql
BEGIN;
  -- Lock both accounts in a consistent order to prevent deadlock
  SELECT balance FROM accounts WHERE account_id IN ('acc_001','acc_002')
    ORDER BY account_id FOR UPDATE;

  -- Debit sender
  UPDATE accounts SET balance = balance - 50.00, updated_at = now()
    WHERE account_id = 'acc_001';

  -- Credit receiver
  UPDATE accounts SET balance = balance + 50.00, updated_at = now()
    WHERE account_id = 'acc_002';

  -- Insert ledger record
  INSERT INTO transactions VALUES (...);
COMMIT;
```

---

## 4. Security Controls

### 4.1 mTLS between services

All internal service-to-service calls (API gateway → transaction service, transaction service → DB) use mutual TLS.

```bash
# Generate a local CA (test only — NOT a public CA)
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -subj "/CN=Homelab Mock CA" -out ca.crt

# Transaction service certificate
openssl genrsa -out txn-service.key 2048
openssl req -new -key txn-service.key \
  -subj "/CN=transaction-service.homelab.local" \
  -out txn-service.csr
openssl x509 -req -in txn-service.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -sha256 -days 365 -out txn-service.crt
```

NGINX gateway — require client cert from the transaction service:

```nginx
ssl_client_certificate /etc/ssl/mock-ca/ca.crt;
ssl_verify_client      on;
ssl_verify_depth       2;
```

### 4.2 JWT authentication for client API

Use an asymmetric key pair (RS256). The gateway verifies the token signature; no shared secret is needed.

```bash
# Generate signing key pair (test only)
openssl genrsa -out jwt-private.pem 2048
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
```

Example decoded JWT payload:

```json
{
  "sub":   "test-client-001",
  "scope": "transactions:read transactions:write",
  "iat":   1730080800,
  "exp":   1730084400
}
```

### 4.3 Structured audit logging (ECS fields)

Every transaction operation writes one row to `audit_log` and also emits a JSON line to stdout:

```json
{
  "@timestamp":     "2026-10-28T02:00:00Z",
  "event.action":   "transaction.created",
  "event.outcome":  "success",
  "transaction.id": "txn_8f3a1b9c",
  "user.id":        "test-client-001",
  "source.ip":      "192.168.10.15",
  "amount":         "50.00",
  "currency":       "USD"
}
```

These lines can be forwarded to a local SIEM (Elasticsearch / Loki / Splunk) for query practice.

### 4.4 Secrets via environment variables

```bash
# Never store these in config files or source code
export DB_URL="postgresql://txn_user:changeme@127.0.0.1:5432/mockledger?sslmode=require"
export JWT_PUBLIC_KEY_PATH="/run/secrets/jwt-public.pem"
export TLS_CERT="/etc/ssl/mock-txn/txn-service.crt"
export TLS_KEY="/etc/ssl/mock-txn/txn-service.key"
```

Use a secrets manager or systemd `EnvironmentFile` (mode `0600`) in production-equivalent homelab setups:

```ini
# /etc/systemd/system/txn-service.service
[Service]
EnvironmentFile=/etc/txn-service/env   # chmod 600, owned by txn-service user
ExecStart=/opt/txn-service/run.py
User=txn-service
```

---

## 5. Testing Approach

### 5.1 Seed data script

```bash
#!/usr/bin/env bash
# seed.sh — populate test accounts, run AFTER migrations
psql "$DATABASE_URL" <<'SQL'
TRUNCATE audit_log, refunds, transactions, accounts RESTART IDENTITY CASCADE;

INSERT INTO accounts (account_id, display_name, balance, currency) VALUES
  ('acc_001', 'Alice Test',   1000.00, 'USD'),
  ('acc_002', 'Bob Test',      500.00, 'USD'),
  ('acc_003', 'Charlie Test',    0.00, 'USD');
SQL
echo "Seed complete."
```

### 5.2 Happy-path test cases

| # | Scenario | Expected outcome |
|---|---------|-----------------|
| H1 | Transfer $50 from acc_001 to acc_002 | 201; acc_001 balance −$50, acc_002 +$50 |
| H2 | GET txn_8f3a1b9c | 200; status = completed |
| H3 | Replay H1 with same idempotency_key | 409; original txn_id returned |
| H4 | Full refund of H1 | 201; acc_001 balance restored |
| H5 | GET refund ref_1a2b3c4d | 200; status = completed |

### 5.3 Failure-mode test cases

| # | Scenario | Expected outcome |
|---|---------|-----------------|
| F1 | Transfer $2000 from acc_001 (balance $1000) | 422; error = insufficient_balance |
| F2 | Refund $75 on a $50 transaction | 422; error = refund_exceeds_original |
| F3 | GET with expired JWT | 401 |
| F4 | POST without Authorization header | 401 |
| F5 | GET /v1/transactions/txn_nonexistent | 404 |
| F6 | POST with amount = −10 | 400; validation error |
| F7 | DB unavailable during transfer | 500; no partial balance change |

### 5.4 Contract testing with pytest

```python
# tests/test_transactions.py
import pytest, requests, os

BASE = os.getenv("API_BASE", "https://transactions.homelab.local/v1")
TOKEN = os.getenv("TEST_JWT")

def auth():
    return {"Authorization": f"Bearer {TOKEN}"}

def test_create_transaction():
    r = requests.post(f"{BASE}/transactions", json={
        "idempotency_key": "test-h1",
        "from_account": "acc_001",
        "to_account":   "acc_002",
        "amount":       "50.00",
        "currency":     "USD",
    }, headers=auth(), verify=False)  # test CA not trusted by default
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "completed"
    assert "transaction_id" in body

def test_idempotency():
    payload = {"idempotency_key": "test-idem-1", "from_account": "acc_001",
               "to_account": "acc_002", "amount": "1.00", "currency": "USD"}
    r1 = requests.post(f"{BASE}/transactions", json=payload, headers=auth(), verify=False)
    r2 = requests.post(f"{BASE}/transactions", json=payload, headers=auth(), verify=False)
    assert r1.status_code == 201
    assert r2.status_code == 409
    assert r2.json()["original_transaction_id"] == r1.json()["transaction_id"]

def test_insufficient_balance():
    r = requests.post(f"{BASE}/transactions", json={
        "idempotency_key": "test-f1",
        "from_account": "acc_001",
        "to_account":   "acc_002",
        "amount":       "99999.00",
        "currency":     "USD",
    }, headers=auth(), verify=False)
    assert r.status_code == 422
    assert r.json()["error"] == "insufficient_balance"
```

Run with:

```bash
# After seeding the database
TEST_JWT=$(python scripts/generate_test_jwt.py) \
  pytest tests/test_transactions.py -v
```

---

## 6. Deployment Summary

```
[ ] PostgreSQL: schema applied; test CA cert in ssl_cert_file; listen_addresses = 'localhost'
[ ] Transaction service: mTLS cert installed; env file chmod 600; systemd unit active
[ ] API gateway (NGINX): ssl_verify_client on; JWT verify_jwt module or Lua snippet loaded
[ ] Redis: bind 127.0.0.1; requirepass set; TLS enabled (redis-server --tls-port 6380)
[ ] Seed script run; all test accounts present
[ ] Happy-path test cases H1–H5 pass
[ ] Failure test cases F1–F7 pass
[ ] Audit log rows visible in PostgreSQL + stdout JSON lines
[ ] Service NOT reachable from outside the homelab network
```

## See also

- [Administration — End-to-End Website Build & Hosting Guide](website-build-and-hosting-guide.md)
- [Deploy TLS Certificates & Harden Web Servers](tls-certificate-deployment.md)
- [Store Service Secrets on Linux](linux-service-secrets-storage.md)
- [Manage Certificates & PKI](certificate-and-pki-management.md)
