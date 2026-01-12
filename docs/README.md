# Configuration Reference

MaveWAF is configured entirely via environment variables. Copy the example file to get started:

```bash
cp docs/.env.example .env
```

## Environment Variables

### Network

| Variable | Description | Required | Default |
|:---|:---|:---:|:---|
| `LISTEN_ADDR` | External address receiving PROXY protocol traffic | ✓ | `0.0.0.0:8080` |
| `INTERNAL_ADDR` | Internal bind address for the engine | ✓ | `127.0.0.1:8081` |
| `BACKEND_URL` | Upstream application URL | ✓ | - |

---

### WAF & Security

| Variable | Description | Default |
|:---|:---|:---|
| `WAF_MODE` | `NORMAL` (standard) or `DEFENSE` (aggressive + CAPTCHA) | `NORMAL` |
| `WAF_BODY_SCAN_ENABLED` | Scan request bodies for payloads | `true` |
| `WAF_BODY_SCAN_MAX_SIZE` | Max body size to scan (bytes) | `32768` |
| `SSRF_ALLOWED_HOSTS` | Comma-separated allowlist for egress | (empty = block all) |

---

### Rate Limiting

MaveWAF uses a two-tier rate limiting system:

| Variable | Description | Default |
|:---|:---|:---|
| `RATE_LIMIT_RPS` | Requests/second per **Circuit** | `6` |
| `RATE_LIMIT_BURST` | Burst allowance per **Circuit** | `10` |
| `RATE_LIMIT_SESSION_RPS` | Requests/second per **Session** | `3` |
| `RATE_LIMIT_SESSION_BURST` | Burst allowance per **Session** | `5` |

---

### Session & CAPTCHA

| Variable | Description | Default |
|:---|:---|:---|
| `SESSION_SECRET` | 32-byte hex key for AES-256-GCM encryption | **Required** |
| `SESSION_EXPIRY_SECS` | Session cookie validity | `3600` |
| `CAPTCHA_ENABLED` | Enable CAPTCHA challenges | `true` |
| `CAPTCHA_SECRET` | Secret for CAPTCHA token signing | **Required** |
| `CAPTCHA_TTL` | Time to solve CAPTCHA (seconds) | `300` |
| `CAPTCHA_STYLE` | `Simple` or `Complex` (AI-resistant) | `Simple` |
| `CAPTCHA_DIFFICULTY` | `easy`, `medium`, or `hard` | `medium` |
| `MAX_CAPTCHA_FAILURES` | Failures before blocking | `3` |
| `CAPTCHA_GEN_LIMIT` | Max CAPTCHAs per session | `5` |

**Generate secrets:**
```bash
# SESSION_SECRET (32-byte hex)
openssl rand -hex 32

# CAPTCHA_SECRET
openssl rand -base64 24
```

---

### Tor Integration

| Variable | Description | Default |
|:---|:---|:---|
| `TOR_CIRCUIT_PREFIX` | IPv6 prefix for circuit ID extraction | `fc00:dead:beef` |
| `TOR_CONTROL_ADDR` | Tor Control Port address | `127.0.0.1:9051` |
| `TOR_CONTROL_PASSWORD` | Plain text password for Control Port | - |
| `TORRC_PATH` | Path to torrc file | `/etc/tor/torrc` |

---

### Defense Thresholds

| Variable | Description | Default |
|:---|:---|:---|
| `DEFENSE_ERROR_RATE_THRESHOLD` | Error ratio (0.0-1.0) to trigger Defense Mode | `0.15` |
| `DEFENSE_CIRCUIT_FLOOD_THRESHOLD` | Requests to flag circuit flood | `100` |
| `DEFENSE_COOLDOWN_SECS` | Seconds before auto-deactivating defense | `300` |

---

### UI & Branding

| Variable | Description | Default |
|:---|:---|:---|
| `APP_NAME` | Website name in footer | `MaveWAF` |
| `LOGO_BASE64` | Base64-encoded favicon | - |
| `META_TITLE` | HTML title for WAF pages | `Security Check` |
| `META_DESCRIPTION` | Meta description | - |
| `META_KEYWORDS` | Meta keywords | - |

---

### Webhooks

| Variable | Description | Default |
|:---|:---|:---|
| `WEBHOOK_ENABLED` | Enable security alert webhooks | `false` |
| `WEBHOOK_URL` | Destination URL for JSON payloads | - |

---

### Logging

| Variable | Description | Default |
|:---|:---|:---|
| `RUST_LOG` | Log level: `error`, `warn`, `info`, `debug`, `trace` | `info` |
| `LOG_FORMAT` | Output format: `json` or `pretty` | `json` |

**Examples:**
```bash
RUST_LOG=warn                    # Production (quiet)
RUST_LOG=debug                   # Development
RUST_LOG=mavewaf=debug,pingora=warn  # Per-module
```

---

### I2P Integration

| Variable | Description | Default |
|:---|:---|:---|
| `I2P_ENABLED` | Enable i2pd hidden service | `false` |

---

### Security Headers

| Variable | Description | Default |
|:---|:---|:---|
| `CSP_EXTRA_SOURCES` | Extra sources to allow for `default`, `script`, `style`, `img`, and `font` src. | (empty) |
| `COOP_POLICY` | `same-origin`, `same-origin-allow-popups`, `unsafe-none`, or `off` | `same-origin-allow-popups` |
| `COEP_ENABLED` | Enable `Cross-Origin-Embedder-Policy: require-corp` | `false` |

**Example:**
```bash
# Allow CDN resources
CSP_EXTRA_SOURCES="https://cdn.example.com https://fonts.example.com"

# Strict isolation (may break cross-origin links)
COOP_POLICY=same-origin

# Enable COEP for SharedArrayBuffer support
COEP_ENABLED=true
```

_Note: Even if `CSP_EXTRA_SOURCES` is enabled, Tor Browser's "Safest" mode may still block external resources (like fonts or scripts) regardless of your CSP settings._

> For more information on HTTP headers, please refer to the [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers).

