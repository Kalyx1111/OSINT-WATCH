# OSINT Watch

Watches up to **50 X/Twitter accounts, 20 Telegram channels and 30 websites** for up to
**50 keyword rules**, and alerts you the moment a match is posted - on this computer's
own notification popup, on your phone, and in a live dashboard - with a link straight to
the original post or page.

By Aryan / @EPureNest

## Before you start - three things that aren't optional

**1. X/Twitter has no working anonymous route any more.** Tools like Nitter that used to
scrape X without an account were shut down after legal action from X in 2026. Getting
X posts now genuinely requires either:
   - X's own API (a paid tier - `https://developer.x.com`), or
   - a third-party paid proxy API such as `twitterapi.io`.

   Either way you get an API key, which goes in **Privacy -> Secrets** once the dashboard
   is running. There is no free or account-free way to do this reliably, and this tool
   will not pretend otherwise or silently fall back to something that scrapes X directly -
   that breaks quickly and can get the source IP blocked.

**2. Telegram works with no account or login at all**, using each channel's public web
preview (`t.me/s/<channel>`) - but only for **public** channels. Private channels, groups
and bots aren't accessible this way, by design.

**3. Websites are fetched politely.** RSS/Atom feeds are used automatically where a site
has one; otherwise headline links are read from the page. `robots.txt` is respected by
default (there's a Settings toggle if you need to override it for a specific reason).

## Setup

1. Install [Python 3.10+](https://www.python.org/downloads/) if you don't have it
   (on Windows, tick "Add python.exe to PATH").
2. Double-click **OswRun.bat** (Windows) or run **`./OswRun.sh`** (macOS / Linux / Termux
   on Android). First run creates a virtual environment and installs dependencies - it
   opens your browser to the dashboard automatically after that.
3. In the dashboard: **Watchlist** to add accounts/channels/sites and keywords,
   **Privacy** to set up a proxy and any API keys, **Notifications** to turn on phone
   push / a Telegram bot / desktop popups and send yourself a test.

No internet on first run? See `wheels/README.txt` for an offline install.

Everything lives in the `data/` folder next to this file - delete it to reset completely.

## Keyword syntax (Watchlist tab)

| Write this | To match |
|---|---|
| `word` | that whole word, any case |
| `"a phrase"` | the exact phrase |
| `missil*` | wildcard - missile, missiles, missilery... |
| `cs:PLA` | case-sensitive term |
| `a + b` | both terms in the same post |
| `!term` | urgent - alerts immediately, skips quiet hours and digest batching |
| `-term` | exclusion - any post matching this is never alerted |

## Getting alerts on your phone

Pick one (or both) in **Notifications**:
- **ntfy** - install the free [ntfy](https://ntfy.sh) app (iOS/Android), pick any topic
  name (long and random, since anyone who knows it can read that topic), put it in
  **Privacy -> Secrets -> ntfy topic**, subscribe to the same topic in the app.
- **Telegram bot** - message [@BotFather](https://t.me/BotFather) to create a bot, put its
  token in **Secrets -> Telegram bot token**, message your new bot once, then put your
  chat ID in **Secrets -> Telegram chat ID** (`@userinfobot` on Telegram will tell you
  yours).

Running this tool itself *on* an Android phone is also possible via
[Termux](https://f-droid.org/packages/com.termux/) - `OswRun.sh` detects Termux and can
use `termux-notification` directly.

## Privacy

- **Strict mode** (default): nothing is ever fetched unless a proxy is configured -
  fetching simply pauses rather than silently going direct. Point it at Tor
  (`127.0.0.1:9150` for Tor Browser, or run `tor` and use `127.0.0.1:9050`; **Detect
  local Tor** finds either one), or any SOCKS5/HTTP proxy.
- No account, cookies, or login is ever used for Telegram or websites. For X, only the
  API key you provide is sent, and only to that API's own server.
- The proxy is sent the destination **hostname**, not an IP - so it resolves DNS, not this
  computer, and nothing about which sites you watch leaks to your own network's DNS
  resolver.
- Secrets (API keys, tokens) are kept in `data/OswSecrets.env`, owner-only permissions,
  never logged (they're redacted even from error messages), never included in exports.
- Website addresses can't point at your own local network (router pages, other apps on
  this machine, cloud-metadata addresses, etc.) unless you deliberately turn that off in
  Settings.
- The dashboard itself only listens on this computer (127.0.0.1) by default.

## Architecture (for reference / modification)

Single folder, flat, every file prefixed `Osw`:

| File | Role |
|---|---|
| `OswApp.py` | entrypoint - hardware check, heartbeat, opens the browser |
| `OswServer.py` | FastAPI app: REST API + live alert stream (SSE) + serves the dashboard |
| `OswEngine.py` | scheduler - polls each source on its own interval, runs keyword matching |
| `OswFetch.py` | the actual fetchers: Telegram preview parser, X (official API / twitterapi.io), RSS/Atom + HTML |
| `OswNet.py` | the only module that touches the network - proxy handling, SSRF/redirect guards, size/time limits |
| `OswNotify.py` | alert delivery - desktop, ntfy, Telegram bot, Termux, and the live dashboard feed |
| `OswMatch.py` | keyword rule parser and matcher |
| `OswConfig.py` | settings/watchlist/secrets - validated, never trusts a hand-edited file blindly |
| `OswStore.py` | SQLite storage (parameterized queries only) |
| `OswHardware.py` | CPU/RAM/disk/Tor/internet check, no extra dependencies |
| `OswFrontend.html` | the dashboard itself - one static file, no build step |
| `tests/` | ~65 automated tests covering matching, validation, network safety, the fetchers, the alert pipeline and the API |

Advanced settings with no dashboard control (edit `data/OswSettings.json` directly, then
restart): `polling.jitter`, `polling.max_backoff`, `server.open_browser`.

## Verifying it yourself

`tests/` ships with the project - 65 automated tests covering the keyword matcher, every
validation rule, the network-safety guards (proxy handling, SSRF, redirects), the actual
fetchers against realistic saved pages, the full poll-to-alert pipeline, and the API. No
extra install needed - from this folder, with the virtual environment active:

```
python -m unittest discover -s tests -p "OswTest*.py"
```

## Troubleshooting

- **"Fetching paused - no proxy"**: you're in strict privacy mode with no proxy set yet.
  Either add one (Privacy tab) or switch to open mode.
- **A source shows "failing"**: hover its error in the Sources tab - it's a plain-language
  reason (wrong handle, blocked by robots.txt, API credits used up, etc.), not a generic
  failure.
- **Desktop notifications don't appear on Linux**: install `libnotify-bin`
  (`sudo apt install libnotify-bin` or your distro's equivalent).
- Logs are in `data/logs/Osw.log` - secrets are always redacted from them.
