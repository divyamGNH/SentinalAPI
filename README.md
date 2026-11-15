# SentinelAPI — local security testing and detection lab

SentinelAPI is a TypeScript/Express API protected by 11 signature/behavior detectors, with PostgreSQL evidence and a React dashboard. It includes a repeatable HTTP simulation runner, offline SecLists corpora, benign controls, run history, and JSON/CSV/HTML reports. No machine learning is used.

## Requirements

- Node.js 22+ and npm
- PostgreSQL 14+ (the commands below use Homebrew PostgreSQL 16 on macOS)
- Three terminals for the API, dashboard, and CLI

Run commands from the project root unless stated otherwise.

## One-time setup

```bash
cd /Users/sohamagarwal/dev/SecDog
npm ci
npm ci --prefix dashboard
brew services start postgresql@16
```

Create the database once if it does not already exist:

```bash
createdb sentinelapi
```

The local defaults work without an env file. To configure them, copy examples only when the destination does not exist:

```bash
test -f .env || cp .env.example .env
test -f dashboard/.env || cp dashboard/.env.example dashboard/.env
```

Root `.env`:

```dotenv
DATABASE_URL=postgresql://localhost:5432/sentinelapi
PORT=3000
FRONTEND_ORIGIN=http://localhost:5173
API_BASE_URL=http://localhost:3000
JWT_SECRET=replace-with-a-long-random-secret
JWT_EXPIRES_IN=8h
ADMIN_USERNAME=admin
ADMIN_PASSWORD=sentinel123
ADMIN_NAME=Security Admin
ENABLE_SIMULATION=true
```

Dashboard `dashboard/.env`:

```dotenv
VITE_API_URL=http://localhost:3000
```

The API seeds the administrator only on first creation. Changing `ADMIN_PASSWORD` does not replace an existing password. Use Account in the UI. Use localhost consistently for the browser and API so the HTTP-only SSE cookie works.

## Start the project

Terminal 1 — API and database:

```bash
cd /Users/sohamagarwal/dev/SecDog
brew services start postgresql@16
npm run dev
```

Terminal 2 — dashboard:

```bash
cd /Users/sohamagarwal/dev/SecDog/dashboard
npm run dev -- --host localhost --strictPort
```

Open **http://localhost:5173**, sign in with `admin / sentinel123` (or your changed credentials), and open **Attack playground**.

Terminal 3 — full standard regression:

```bash
cd /Users/sohamagarwal/dev/SecDog
npm run sim -- --all
```

The runner sends requests automatically; no Enter prompts. It prints each PASS/FAIL with actual status, latency, and persisted alert IDs. It writes three files to `reports/` and saves the same run in PostgreSQL.

Check the API/database:

```bash
curl http://localhost:3000/health
```

Expected: `{"status":"ok","database":"connected"}`. Press Ctrl+C in API/dashboard terminals to stop them.

## Available simulation commands

```bash
# Preview every planned scenario and request count without contacting the API
npm run sim -- --list

# Full controlled suite: 175 requests with default 20 password guesses
npm run sim -- --all

# Selected injection scenarios
npm run sim -- --scenario sqli,xss,command,traversal

# Dictionary guessing with 100 candidates from the included community wordlist
npm run sim -- --scenario brute --wordlist attack-sim/fixtures/passwords.txt --password-limit 100

# Your own newline-separated password file (5–1,000 entries; 5–200 guesses/run)
npm run sim -- --scenario brute --wordlist ./my-passwords.txt --password-limit 100

# Password spraying: same password across 10 lab usernames
npm run sim -- --scenario spraying

# Bounded single-source request flood + cooldown check
npm run sim -- --scenario flood

# Negative controls: normal requests should not produce alerts
npm run sim -- --scenario benign

# Add 120 raw SecLists SQL/XSS probes to the standard suite: 295 requests
npm run sim -- --profile extended --all

# Only baseline + raw community SQL/XSS probes: 142 requests
npm run sim -- --profile extended --scenario sqli,xss

# Select an output directory
npm run sim -- --scenario ssrf,upload,scanner --output ./reports/demo

# Help
npm run sim -- --help
```

`npm run test:sim` is an alias for the new automatic runner.

For another database-backed account, or after changing your admin password:

```bash
SENTINEL_USERNAME=analyst1 SENTINEL_PASSWORD='YourPassword' npm run sim -- --all
```

These credentials authenticate the runner to the dashboard API. Dictionary guesses target the separate lab `POST /login`, whose valid demonstration credential is `admin / password123`. They do not guess your dashboard password.

CLI exit codes: **0** when every completed check passes; **1** for failed checks, a failed/cancelled run, invalid configuration, or connection/auth errors. Extended runs can intentionally reveal missing signatures and therefore return 1 even when the engine completed normally.

## Standard scenario counts and expectations

| Scenario key | Requests | Verification |
|---|---:|---|
| benign | 12 | Normal query, nested JSON, upload, public-fetch simulation, valid lab login: HTTP 200 and no alerts |
| sqli | 12 | Boolean, UNION, stacked statements, timing signatures, encoded input: HTTP 403 plus SQL Injection alert |
| xss | 10 | Script, event handler, SVG, iframe, case/encoding variants: HTTP 403 plus XSS alert |
| traversal | 6 | Unix/Windows and encoded paths: HTTP 403 plus traversal alert |
| command | 10 | Shell separators, substitutions, newline, encoded input: HTTP 403 plus command alert |
| brute | 20 | First four wrong guesses: 401; from fifth: 403 plus brute-force alert |
| spraying | 10 | First four distinct users: 401; from fifth: 403 plus Credential Stuffing alert |
| ssrf | 8 | Loopback/private IPv4, metadata, IPv6 loopback, integer IPv4: HTTP 403 plus SSRF alert |
| upload | 4 | MZ, PHP, shell script, ELF signatures: HTTP 403 plus upload alert |
| scanner | 6 | Known scanner User-Agent strings: HTTP 403 plus scanner alert |
| enumeration | 15 | Missing routes return 404; fifteenth has an enumeration alert |
| flood | 62 | 60 requests, up to 10 concurrent workers; subsequent request must return 429 with a persisted flood alert; a recovery request after 31 seconds must return 200 |
| **Total** | **175** | Response status **and** case-linked database evidence |

The full run takes about 32–40 seconds because it waits for the real cooldown and verifies recovery. You can cancel during this wait.

The flood detector triggers at 50 requests within 10 seconds and blocks for 30 seconds. This is a single-host HTTP flood, not a distributed traffic generator.

Dictionary trials use independent batches of up to 25 guesses so the 50-request flood threshold does not mask the brute-force detector. Different scenarios and users have separate state. Simulator headers are validated against an active, owned run and known case IDs. Completing/cancelling a run releases its transient state; normal traffic and previous alert history remain intact. The spraying window expires after 60 seconds; brute force uses 30 seconds and enumeration 20 seconds.

## Community corpus and limits

Source: [SecLists](https://github.com/danielmiessler/SecLists), pinned to revision `ab068333d7d44a9376e2037b0ed7d2e8ca5c6610`.

- 1,000 common passwords bundled offline.
- 268 generic SQL probes and 110 XSS probes bundled offline.
- Extended profile replays the first 60 SQL and first 60 XSS corpus lines.
- Standard positive/negative cases are project-authored; dictionary candidates come from SecLists.
- Upstream paths, attribution, and MIT license are in `attack-sim/fixtures/`.

The runner targets loopback origins only. The server worker sends traffic only to its own loopback port. `ENABLE_SIMULATION=false` or `NODE_ENV=production` prevents new runs.

The lab inspects requests; it does not execute SQL/shell commands, render supplied script HTML, or fetch supplied URLs. A missing signature is evidence of a detection coverage gap, not proof of remote code execution or another successful exploit. Raw community probes include incomplete/context-dependent syntax. Pass counts describe these inputs, not protection against every real-world attack. SSRF checks are lexical; DNS rebinding and full destination validation are outside this simulated fetch endpoint.

Methodology reference: [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/). This project uses positive/negative controls and recorded evidence; it does not claim to implement the complete OWASP testing guide.

## Dashboard and demonstration flow

1. Sign in. **Overview** explains the project and summarizes the latest saved experiments.
2. Open **Attack playground** and choose SQL injection. Each of the 11 attacks has a runnable workspace; Normal traffic provides the control scenario.
3. Keep Standard and **Guided** speed, then click **Start experiment**. Serial requests are spaced by 700 ms for demonstration. Flood traffic remains concurrent to preserve its behavior. Choose **Fast** for quick evidence collection.
4. Follow **Request sent → Security inspection → API decision → Evidence saved**. The diagram visualizes verified responses, not internal tracing. Inspect the submitted input, matched rule, real response body, alert IDs, and actual outcome.
5. Use the **Request timeline** to select any response. Behavioral scenarios also show a clickable sequence of responses to explain thresholds, blocking, and recovery.
6. **Blocked**, **Allowed**, **Login rejected**, **Rate limited**, and **Detection gap** describe actual behavior. **Matches expectation** is a separate check; it never means an attack succeeded.
7. Expand **Try your own input / advanced options** on SQL, XSS, command, traversal, SSRF, or scanner scenarios. Enter a local probe and choose its expected block/allow behavior. The app sends one real request and compares the response with that expectation. Password guessing supports a custom text wordlist.
8. Choose **Full suite** from the playground for all scenarios (175 Standard requests with 20 password attempts). Use Extended to add SQL/XSS community probes and investigate **Unexpected** results. The standard suite is curated; passing it does not establish complete protection.
9. Open **Results** to revisit saved runs and replay their recorded evidence. Replay sends no new requests. Download JSON, CSV, or HTML; print HTML to save a PDF if needed. Older runs retain the evidence fields available when they were recorded.
10. Open **Activity → Detections** to inspect actual alert records and Acknowledge, Resolve, or Reopen them. **Sign-in history** and **Audit trail** live in the same Activity section. Theory-only attack pages have been replaced by runnable scenarios with short explanations beside the evidence.

Admin can view all users' simulations and alerts. Analysts see only their own reports and alerts and can run experiments. Viewer accounts can inspect their own reports but cannot start simulations. One active run per user and at most four active runs are permitted; use **Stop experiment** to cancel. Runs interrupted by API restart are marked failed and retain saved partial results.

To show account isolation, create an analyst under **Team**, then run the CLI with that account's `SENTINEL_USERNAME` and `SENTINEL_PASSWORD`. As admin choose **Activity → Detections → All users → analyst1**. The analyst cannot retrieve another account's run/report or admin-wide alert history.

## Evidence storage

The API creates additive schema changes automatically:

- `users`: bcrypt hashes and roles.
- `auth_events`: successful/failed dashboard login and logout.
- `audit_events`: account, investigation, and simulation actions.
- `alerts`: user ownership, status/actor/timestamps, `simulation_id`, and `simulation_case_id`.
- `simulation_runs`: owner, configuration (no password values), progress, outcomes, and full report.
- `audit_integrity_checkpoint`: signed audit head and event count for detecting edits or missing records after audit signing starts.

Local JSON/CSV/HTML artifacts go to `reports/` (Git-ignored). Alerts/events display the newest 250 records; simulations display the latest 30 runs. Full evidence for an individual run is retained in its report.

## Defense Lab and investigation demo

1. Open **Defense lab → Rule comparison**. The practice rule and the current SQL signature evaluate the same 21 labeled search fixtures offline. The practice rule flags 7 of 12 suspicious cases and 1 of 9 normal cases. The current signature flags 12 of 12 suspicious cases and 0 of 9 normal cases. Use **Show changes only** to highlight the six corrected outcomes. These figures describe the included fixtures.
2. In a new experiment, select an individual request under **Request timeline**, then open **Explain this decision** in the response panel. Signature decisions show the rule and input field. Behavior decisions can show the actual count, threshold, and time window, even before a block. Structured explanations are available for requests recorded after this update.
3. Open **Activity → Incidents**, or choose **View incident** in an experiment with alerts. The timeline groups saved detections, run events, review verdicts, and investigation actions by experiment. Administrators can see all incidents. Other accounts see their own.
4. Set an alert's **Review verdict** to Confirmed detection, False positive, or Needs review. This verdict is separate from the Open, Acknowledged, or Resolved status. Expand **Review totals by detector** in Detections to see counts for your account scope. Viewers can read verdicts. Analysts can change their own, and administrators can change verdicts across accounts.
5. As an administrator, open **Defense lab → Audit integrity**. **Verify audit trail** checks the stored signed events. **Run demonstration** tests an edited record or deleted final record on a disposable sample. Start a new normal-traffic experiment if the log has no signed events yet.

Each new audit event is authenticated with HMAC-SHA256 and linked to the preceding signature. A signed checkpoint records the last event and expected count. Records from before the upgrade remain outside the signed range. The check assumes the signing key is kept private and the full database has not been reverted to an earlier matching snapshot. For a fresh installation, set a stable `AUDIT_INTEGRITY_SECRET` before starting. The local configuration uses `JWT_SECRET` when no dedicated audit key is set. Keep the key used to sign existing entries stable.

## Verification commands

```bash
# Compiler + detector regression tests + dashboard build/lint
npm run check

# Detector/state/report tests without running PostgreSQL
npm test

# End-to-end HTTP + PostgreSQL evidence verification against the running API
npm run sim -- --all
```

Tests cover nested/encoded inputs, benign apostrophes, brute-force boundaries/expiry/reset, user-state separation, spraying uniqueness/expiry/redaction, flood threshold, SSRF URL normalization, plan validation, and safe HTML/CSV report exports.

## Troubleshooting

- Connection refused: start the API and PostgreSQL; check `curl http://localhost:3000/health`.
- Homebrew says started but PostgreSQL is unavailable: `brew services restart postgresql@16`.
- Login fails: use your current account password, not necessarily the original default. Set runner credentials as shown above.
- Frontend port occupied: stop your previous Vite terminal or choose a different port and update `FRONTEND_ORIGIN`.
- Live stream reconnecting: use localhost consistently; restart the API after code/config changes.
- Extended suite exits 1: inspect the HTML report or the Unexpected filter in Results. A completed experiment with differing expectations is a valid measured result.
- No internet during the demo: all payloads/wordlists are bundled; running tests does not need external downloads.
