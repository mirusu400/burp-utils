# burp-export-import

Burp Suite extension (works on Community + Pro) that exports/imports Proxy History and Repeater state as HAR or JSON.

## Features

- **History Export** (HAR / JSON) with domain filter — comma-separated, supports wildcards like `*.example.com` — and date range filter (`YYYY-MM-DD` or `YYYY-MM-DD HH:mm[:ss]`, local time; empty = no bound).
- **History Import** (HAR / JSON) — entries are added to the **Site Map** (Burp's Montoya API does not expose write-access to Proxy History).
- **Repeater Export** (HAR / JSON) — Repeater tabs cannot be read directly via the Montoya API. Instead, right-click any request in Proxy/Target/Repeater/etc. and pick **"Add to Repeater Export Collection"**. The collection is what gets exported.
- **Repeater Import** (HAR / JSON) — each entry is re-created as a real Repeater tab via `Repeater.sendToRepeater()`.

## Build

Requires JDK 17+ and Gradle.

```sh
gradle build
```

Output jar: `build/libs/burp-export-import-1.0.0.jar` (fat jar — includes Gson).

## Install

1. Burp → Extensions → Installed → Add
2. Extension type: Java
3. Select the built jar.
4. A new **Export/Import** top-level tab appears.

## File formats

### HAR

Standard HAR 1.2 plus a few `_burp*` fields (`_burpRaw`, `_burpHost`, `_burpPort`, `_burpSecure`, `_burpTabName`) to preserve exact request/response bytes and Repeater metadata. Other HAR tools ignore the `_burp*` keys but the common parts remain readable.

### JSON

Simple round-trip format. Base64-encoded raw request/response bytes plus host/port/secure metadata. No loss.

```json
{
  "format": "burp-export-import/v1",
  "entries": [
    {
      "url": "https://example.com/x",
      "method": "GET",
      "host": "example.com",
      "port": 443,
      "secure": true,
      "httpVersion": "HTTP/1.1",
      "startedDateTime": "2026-04-22T...",
      "tabName": null,
      "request": "<base64>",
      "response": "<base64>"
    }
  ]
}
```

## Limitations (Montoya API)

- Proxy History is read-only; imported entries show up in Site Map, not Proxy History.
- Existing Repeater tabs cannot be enumerated, so Repeater export requires explicit "add to collection" action.

## Domain filter syntax

- `example.com` — host equals or ends with `.example.com`
- `*.example.com` — subdomains of `example.com` plus `example.com` itself
- `a.com, b.com` — OR
- (empty) — no filter
