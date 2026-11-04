# Burp Suite ↔ Optio integration

Two directions, independent — use either or both.

## Forward Optio → Burp (send traffic to Burp)

In Optio, open **Config** on a target and either type your proxy or click
**Route through Burp (127.0.0.1:8080)**. From then on:

- the **request runner** ("Send request") and
- every **tool** Optio launches (via `HTTP(S)_PROXY`)

route through Burp. Turn off **verify TLS** in the same dialog so Burp's CA
doesn't break HTTPS. A `⇄ proxy` badge in the header shows when routing is on.

## Sync Burp → Optio (pull traffic from Burp, live)

`optio_sync.py` is a Burp extension that POSTs each **in-scope** request+response
to Optio's `/ingest` endpoint as you browse. Optio records it as a captured
request and grows the attack-surface graph from it.

1. Configure Jython in Burp: **Extensions → Settings → Python environment →**
   select a `jython-standalone-2.7.x.jar`.
2. **Extensions → Installed → Add →** Extension type **Python** → select
   `optio_sync.py`.
3. Set your engagement scope under **Target → Scope** (only in-scope traffic is
   forwarded, so Optio stays clean).
4. Make sure Optio is running (`uv run optio`, default web port **8788**). If you
   serve Optio on another port, edit `OPTIO_URL` at the top of `optio_sync.py`.

Each forwarded request auto-associates to a target by host (creating it if new),
so browsing an app through Burp makes its surface appear in Optio in real time.

### No Burp extension handy?

Any client can POST the same shape to `/ingest`:

```json
{ "method": "GET", "url": "https://app.example.com/login",
  "status": 200, "req_headers": {}, "resp_headers": {}, "resp_body": "…" }
```
