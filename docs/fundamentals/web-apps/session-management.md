---
title: "Fundamentals — Session Management & Cookie Security"
description: "Web session lifecycle engineering, cookie security attributes (__Host- prefixes, HttpOnly, Secure), session fixation defense, and idle timeouts."
platforms: [Linux, Windows]
languages: [HTTP, Python, PowerShell]
tasks: [Hardening, Administration, Investigation]
type: entry
verified: true
last_verified: 2026-10-06
difficulty: intermediate
---

# Session Management & Cookie Security

Web applications use **Session Management** to maintain authenticated state across stateless HTTP requests. Because a valid session identifier grants complete access to a user's account without requiring password re-entry, session tokens are prime targets for adversaries.

Securing session management requires cryptographically unpredictable token generation, defensive cookie flags (`Secure`, `HttpOnly`, `SameSite`), strict session fixation defenses (token rotation upon login), and enforced idle/absolute timeouts.

---

## Session Architecture: Stateful vs. Stateless

```mermaid
graph TD
    subgraph Stateful Sessions (Server-Tracked)
        C1[Client Browser] -->|Cookie: session_id=abc| S1[Application Server]
        S1 -->|Lookup session_id| R1[(Redis / Database)]
        R1 -->|Return User ID & Permissions| S1
        Note1[Pros: Immediate instant revocation.<br>Cons: Requires centralized memory store.]
    end

    subgraph Stateless Sessions (JWT / Client-Held)
        C2[Client Browser] -->|Authorization: Bearer JWT| S2[Application Server]
        S2 -->|Verify Cryptographic Signature| S2
        Note2[Pros: Highly scalable horizontally.<br>Cons: Hard to invalidate before exp.]
    end
```

---

## Session Vulnerabilities & Attacks

| Attack | How It Works | Defense Strategy |
|:---|:---|:---|
| **Session Fixation** | Attacker obtains a valid anonymous session ID, tricks the victim into logging in with it, and uses the known ID to hijack the authenticated account. | **Always regenerate/rotate the session ID immediately upon successful authentication.** |
| **Session Hijacking** | Attacker intercepts or steals a session token via XSS (`document.cookie`) or unencrypted Wi-Fi (AiTM). | Mark cookies **`HttpOnly`** and **`Secure`**; enforce HTTPS exclusively via HSTS. |
| **Session Replay** | Attacker captures a stale token that was never invalidated by the server. | Enforce strict server-side **Idle Timeouts** (e.g., 15 minutes) and **Absolute Timeouts** (e.g., 8 hours). |
| **Subdomain Injection** | A vulnerable subdomain (`blog.corp.com`) overwrites or reads cookies set for the parent domain (`corp.com`). | Use modern **`__Host-` cookie prefixes** which restrict the cookie strictly to the origin domain and path `/`. |

---

## The `__Host-` Cookie Prefix Standard

Modern browsers implement strict security rules when a cookie name starts with `__Host-`:

```http
Set-Cookie: __Host-SessionId=a1b2c3d4e5f6; Secure; HttpOnly; SameSite=Strict; Path=/
```

### Browser Requirements for `__Host-` Cookies:
1. Must include the **`Secure`** flag (only transmitted over HTTPS).
2. Must be sent from a secure origin (HTTPS).
3. Must **omit the `Domain` attribute** (ensuring it cannot be read or set by subdomains).
4. Must set **`Path=/`**.

---

## Practical Examples

### 1. Python: Secure Stateful Session Manager with Token Rotation

```python
import secrets
import time
from typing import Optional, Dict

class SecureSessionStore:
    """In-memory session manager with idle timeouts, absolute timeouts, and rotation."""
    def __init__(self, idle_timeout_sec: int = 900, max_lifetime_sec: int = 28800):
        self.idle_timeout = idle_timeout_sec      # 15 minutes
        self.max_lifetime = max_lifetime_sec      # 8 hours
        self.sessions: Dict[str, dict] = {}

    def create_session(self, user_id: str) -> str:
        """Generates a cryptographically strong 256-bit session token."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.sessions[token] = {
            "user_id": user_id,
            "created_at": now,
            "last_accessed": now
        }
        return token

    def validate_session(self, token: str) -> Optional[str]:
        """Validates token presence, checks timeouts, and slides idle window."""
        session = self.sessions.get(token)
        if not session:
            return None

        now = time.time()
        # 1. Check absolute maximum lifetime
        if now - session["created_at"] > self.max_lifetime:
            self.destroy_session(token)
            return None

        # 2. Check idle timeout
        if now - session["last_accessed"] > self.idle_timeout:
            self.destroy_session(token)
            return None

        # Slide idle window
        session["last_accessed"] = now
        return session["user_id"]

    def rotate_session(self, old_token: str) -> str:
        """Crucial defense against session fixation: destroys old token and issues fresh token."""
        user_id = self.validate_session(old_token)
        if not user_id:
            raise ValueError("Cannot rotate an invalid or expired session.")
            
        self.destroy_session(old_token)
        return self.create_session(user_id)

    def destroy_session(self, token: str) -> None:
        self.sessions.pop(token, None)
```

---

### 2. PowerShell: Auditing Cookie Security Flags and Prefixes

```powershell
function Get-WebCookieSecurityPosture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Uri]$Uri
    )

    try {
        $wr = [System.Net.HttpWebRequest]::Create($Uri)
        $wr.AllowAutoRedirect = $false
        $resp = $wr.GetResponse()

        $rawCookies = $resp.Headers.GetValues("Set-Cookie")
        if (-not $rawCookies) {
            Write-Host "No Set-Cookie headers returned by $Uri" -ForegroundColor Yellow
            return
        }

        foreach ($cookie in $rawCookies) {
            $nameVal = ($cookie -split ';')[0].Trim()
            $name = ($nameVal -split '=')[0]

            [PSCustomObject]@{
                TargetEndpoint = $Uri.Host
                CookieName     = $name
                UsesHostPrefix = $name.StartsWith("__Host-")
                HasSecure      = ($cookie -match '(?i)\bSecure\b')
                HasHttpOnly    = ($cookie -match '(?i)\bHttpOnly\b')
                SameSite       = if ($cookie -match '(?i)SameSite=(Strict|Lax|None)') { $Matches[1] } else { 'None/Unset' }
            }
        }
    }
    catch {
        Write-Error "Failed to probe $Uri : $_"
    }
}

# Example Usage:
# Get-WebCookieSecurityPosture -Uri "https://portal.contoso.com" | Format-Table -AutoSize
```

---

## Related References

- [OWASP Top 10 for Web Applications](owasp-web-top-10.md) — Category A07: Identification and Authentication Failures.
- [Cross-Site Scripting (XSS) & CSP](xss-defense.md) — Protecting cookies from client-side script exfiltration.
- [Cross-Site Request Forgery (CSRF) & State Defense](csrf-defense.md) — Cookie SameSite attributes and ambient credentials.
- [Authentication & Token Lifecycles](../apis/auth-tokens.md) — OAuth 2.0 token caching and Bearer token lifecycles.
