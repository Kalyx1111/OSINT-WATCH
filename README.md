# OSINT WATCH

---

#### 🛰️ OSINT WATCH — Intelligence Monitoring & Alert Platform

**OSINT WATCH** is a security-focused OSINT monitoring platform designed to continuously watch selected **X accounts, Telegram public channels, and websites** against configurable keyword rules.

It combines automated collection, keyword matching, SQLite storage, source-linked alerts, live dashboard feeds, proxy-aware networking, security controls, diagnostics, and multi-channel notifications in a single deployable project.

**Built for controlled, source-linked monitoring — not blind scraping.**

---

#### 🎯 CORE CAPABILITIES

* Monitor up to **50 X accounts**
* Monitor up to **20 Telegram public channels**
* Monitor up to **30 websites**
* Configure up to **50 keyword rules**
* Match words, phrases, wildcards, case-sensitive terms, AND conditions, urgent terms and exclusions
* SQLite-based local data store
* Silent baseline on first run to prevent an initial alert storm
* Continuous polling and alert processing
* Every alert includes the **original source link**

---

#### 📡 SUPPORTED SOURCES

**X / Twitter**

* Official X API supported
* Paid third-party provider such as `twitterapi.io` supported
* API credentials stored through the dashboard Secrets panel
* No free or anonymous X monitoring route is assumed

**Telegram**

* Public Telegram channels supported through public web preview
* No Telegram login/account required
* Private channels and private groups are not supported

**Websites**

* RSS/Atom auto-discovery
* HTML fallback when RSS/Atom is unavailable
* `robots.txt` respected by default
* Headline links can be monitored when structured feeds are unavailable

---

#### 🔎 KEYWORD MATCHING ENGINE

The monitoring engine supports configurable matching rules including:

* Word matching
* Phrase matching
* Wildcards
* Case-sensitive matching
* AND conditions
* Urgent keywords
* Exclusion keywords
* Multiple independent keyword rules

This allows the watchlist to be configured around specific monitoring requirements rather than generating unrestricted alerts.

---

#### 🚨 ALERT & NOTIFICATION SYSTEM

OSINT WATCH supports multiple notification channels:

* 🖥️ Desktop popup
* 📱 ntfy phone push
* 🤖 Telegram bot
* 📲 Android Termux
* 🌐 Live dashboard feed
* 🔗 Original source link attached to every alert

The notification dispatcher includes:

* Quiet hours
* Burst digest handling
* Alert redaction
* Background notification processing
* Controlled shutdown behavior

---

#### 🖥️ LIVE DASHBOARD

The project includes a **dark tactical-style dashboard** with:

* Live intelligence feed
* Server-Sent Events (**SSE**)
* Watchlist editor
* Keyword rule management
* Settings
* Secrets vault
* Diagnostics
* Monitoring configuration
* Alert visibility
* Source-linked intelligence entries

The watchlist editor enforces the configured monitoring limits:

* **50 X accounts**
* **20 Telegram channels**
* **30 websites**
* **50 keyword rules**

---

#### 🔐 NETWORK SECURITY

OSINT WATCH uses a security-focused network layer designed to reduce unnecessary exposure.

**Fail-closed strict mode**

* Network fetching can be configured to require a proxy
* No silent direct-network fallback when strict proxy requirements are enabled

**Proxy support**

* Tor
* SOCKS5
* HTTP proxy
* Remote DNS through proxy

**SSRF protection**

* Guards against dangerous user-entered URLs
* Redirect validation
* DNS-related protections
* Host-header protection
* DNS-rebinding protection

**Privacy-oriented behavior**

* No cookies required for supported public-source collection
* No account/IP exposure is intentionally introduced by the monitoring layer
* Secrets are redacted from logs

---

#### 🛡️ APPLICATION SECURITY

Security controls implemented and tested include:

* CSRF protection
* Host-header validation
* DNS-rebinding protection
* SSRF guards
* Redirect validation
* Zero-trust input validation
* Secrets redaction
* Owner-only file permissions
* Controlled configuration validation

The project also uses security auditing during verification.

---

#### 🗄️ LOCAL DATA & STORAGE

OSINT WATCH uses **SQLite** for its local data store.

The project keeps monitoring information locally rather than requiring a separate database server.

Configuration and application data are separated from the application code location so that the project can be relocated without breaking the frontend data path.

---

#### 🧪 VERIFICATION & TESTING

OSINT WATCH was not treated as a mock-up.

The project went through automated and live-process verification.

**Automated verification:**

* **65 automated tests shipped with the package**
* Matcher tests
* Validation-rule tests
* SSRF tests
* Proxy tests
* Redirect-guard tests
* Realistic saved-page fetcher tests
* Poll-to-alert pipeline tests
* API tests
* Shutdown behavior tests

**Security verification:**

* **Bandit: 0 issues**
* **pip-audit: 0 vulnerabilities**

---

#### 🔬 REAL LIVE-PROCESS TESTING

The actual application was also tested as a live process rather than relying only on unit tests.

The live verification included:

* Server boot
* Real HTTP requests
* Endpoint checks
* Process shutdown
* Clean extraction of the final ZIP
* Fresh application boot from the extracted package

The live testing discovered and fixed five real issues that unit tests alone had not exposed:

1. Dispatcher shutdown race writing to a closed database
2. `OSW_HOME` relocation/data-folder override issue
3. Host-header guard interfering with DNS-rebinding protection
4. Open SSE connection potentially blocking shutdown indefinitely
5. Crash-recovery marker being written from code that did not reliably execute during shutdown

All five issues were fixed and re-verified.

---

#### ⚙️ SHUTDOWN & SSE HANDLING

The application uses bounded shutdown behavior for lingering connections.

Testing confirmed that an open SSE connection cannot hold the server indefinitely.

The shutdown path was corrected to:

* Detect connection/disconnect behavior
* Use bounded graceful shutdown
* Force-cancel lingering tasks when required
* Ensure application shutdown handling occurs in the reliable FastAPI lifespan path

The final live test confirmed that the process exits within the configured shutdown grace period.

---

#### 📊 INTELLIGENCE MONITORING WORKFLOW

```text
X / Telegram / Websites
          ↓
       Fetchers
          ↓
   Network Security
          ↓
   Content Extraction
          ↓
   Keyword Matcher
          ↓
      SQLite Store
          ↓
   Alert Dispatcher
          ↓
 ┌────────┼─────────┐
 ↓        ↓         ↓
Desktop  Phone    Telegram
 ↓        ↓         ↓
Termux   ntfy    Bot Alerts
          ↓
    Live Dashboard
```

---

#### 🧰 RUNNING OSINT WATCH

**Windows**

Double-click:

```text
OswRun.bat
```

**Mac / Linux / Termux**

```bash
./OswRun.sh
```

The launcher:

* Creates the required Python environment
* Installs dependencies
* Starts the application
* Opens the dashboard in the browser

---

#### 🔑 API CREDENTIALS

For sources requiring credentials, such as the X API or supported paid third-party providers:

* Credentials are entered through the dashboard Secrets panel
* Secrets are not intended to be stored in normal application logs
* Do not commit API keys, bot tokens, passwords, or private credentials to GitHub

---

#### ⚠️ IMPORTANT SOURCE LIMITATIONS

**X / Twitter**

There is no free or anonymous X monitoring route assumed by this project.

Use either:

* Official paid X API access
* A supported paid third-party provider such as `twitterapi.io`

**Telegram**

Only **public channels through the public web preview** are supported.

Private channels/groups are not supported by this implementation.

**Websites**

The website collector uses:

1. RSS/Atom when available
2. HTML fallback when necessary

`robots.txt` is respected by default.

---

#### 🧱 SECURITY MODEL

OSINT WATCH is designed around a **fail-closed and zero-trust approach**:

```text
User Input
    ↓
Validation
    ↓
Security Guards
    ↓
Proxy / Network Policy
    ↓
Fetcher
    ↓
Content Processing
    ↓
Keyword Matching
    ↓
SQLite
    ↓
Redacted Alert
    ↓
Source-linked Notification
```

---

#### 📁 PROJECT STRUCTURE

The delivered package contains the application, configuration, runtime components and verification suite required for deployment.

The package also includes:

```text
tests/
```

with the automated verification suite used during development and final validation.

---

#### 🧪 FINAL PACKAGE VERIFICATION

The exact ZIP intended for delivery was:

1. Extracted into a clean location
2. Checked for missing components
3. Tested with the included test suite
4. Booted as an application
5. Verified through live HTTP interaction
6. Checked for clean shutdown behavior

This provides verification of the packaged build rather than only the development workspace.

---

#### 🚀 DEPLOYMENT MODEL

OSINT WATCH can be deployed as a local monitoring platform where the operator runs the application and accesses the dashboard through a browser.

The monitoring engine, database, alert dispatcher and dashboard operate as one integrated application.

---

#### 🔮 FUTURE EXPANSION

Potential future development areas include:

* Additional intelligence-source connectors
* More notification providers
* Expanded correlation and enrichment
* Advanced event deduplication
* Historical intelligence search
* Additional dashboard analytics
* More configurable collection schedules
* Expanded structured OSINT feeds

---

#### 📌 IMPORTANT

OSINT WATCH is intended for **lawful, authorized and responsible OSINT monitoring**.

Users are responsible for complying with the terms of service, access rules, privacy requirements, robots directives, applicable laws and any organizational policies governing the sources they monitor.

The project does **not** provide unrestricted access to private accounts, private Telegram groups, or authenticated X data without appropriate credentials.

---

#### ✅ CURRENT STATUS

**Build status: VERIFIED PACKAGE**

* Core monitoring engine implemented
* X / Telegram / website fetchers implemented
* Keyword matching implemented
* SQLite storage implemented
* Multi-channel alerts implemented
* Live SSE dashboard implemented
* Proxy/security layer implemented
* SSRF protections implemented
* Secrets redaction implemented
* 65 automated tests included
* Bandit: 0 issues
* pip-audit: 0 vulnerabilities
* Live-process testing completed
* Shutdown issues fixed and re-verified
* Clean ZIP extraction and boot verified

---
