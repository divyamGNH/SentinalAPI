# SentinelAPI Report

## Overview
SentinelAPI implements a custom intrusion-detection middleware designed to protect a Node.js REST API. Unlike modern anomaly-based detection systems or Web Application Firewalls (WAFs) that rely on Machine Learning (ML), SentinelAPI operates purely on **signature and heuristic-based detection**. It inspects incoming request payloads, headers, and metadata against hardcoded patterns and thresholds. While simple and extremely fast, signature-based systems can be bypassed by novel obfuscation techniques, highlighting the need for defense-in-depth in production environments.

---

### 1. SQL Injection (SQLi)
**What it is:** Attackers inject malicious SQL commands into input fields to manipulate backend database queries, potentially extracting or deleting sensitive data.
**Real-world Defense:** Using Parameterized Queries (Prepared Statements) or ORMs to ensure input is treated strictly as data, not executable code.
**SentinelAPI Approach:** Signature-based. Uses a Regular Expression to detect common SQLi syntax like `UNION SELECT` or comment characters (`--`) in the query parameters or request body.

### 2. Cross-Site Scripting (XSS)
**What it is:** Attackers inject malicious JavaScript into input fields that is later reflected or stored and executed in the browsers of victim users.
**Real-world Defense:** Context-aware output encoding (escaping HTML entities) and implementing a strong Content Security Policy (CSP).
**SentinelAPI Approach:** Signature-based. Recursively scans normalized incoming text payloads for `<script>` tags and dangerous attributes like `onerror=` using regex.

### 3. Path Traversal
**What it is:** Attackers manipulate file paths using `../` sequences or absolute paths to access files outside the intended web root directory (e.g., `/etc/passwd`).
**Real-world Defense:** Normalizing paths before resolving them, using safe API functions like `path.basename()`, and running the application with least privilege.
**SentinelAPI Approach:** Signature-based. Inspects request paths and payloads for `../`, URL-encoded equivalents (`%2e%2e%2f`), and known sensitive paths.

### 4. Command Injection
**What it is:** Attackers append shell metacharacters (like `;` or `|`) to input fields that the server later executes in a system shell, allowing arbitrary command execution.
**Real-world Defense:** Avoiding shell execution entirely (e.g., using native library equivalents) or strictly sanitizing input if executing a binary is unavoidable.
**SentinelAPI Approach:** Signature-based. Uses regex to look for metacharacters followed by common Unix commands (like `rm`, `cat`, `whoami`).

### 5. Brute-Force Login
**What it is:** Attackers repeatedly guess passwords against a single account until the correct one is found.
**Real-world Defense:** Account lockout mechanisms, increasing delays between attempts, and Multi-Factor Authentication (MFA).
**SentinelAPI Approach:** Heuristic-based. Maintains an in-memory sliding window tracking failed login attempts per IP and username. Triggers if 5 failures occur within 30 seconds.

### 6. Credential Stuffing
**What it is:** Attackers use large databases of compromised passwords (from previous breaches) and test them automatically across many different accounts on a target site.
**Real-world Defense:** Checking passwords against known breached databases (e.g., HaveIBeenPwned), MFA, and behavioral CAPTCHAs.
**SentinelAPI Approach:** Heuristic-based. Tracks if a single IP address attempts to use the *same password* against multiple *distinct usernames* within a 60-second sliding window. This same-password/many-user scenario is more precisely called password spraying. Password values are hashed in detector state and redacted from alerts.

### 7. Request Flood / DDoS
**What it is:** Attackers overwhelm the application with a massive volume of requests, exhausting server resources and causing a Denial of Service.
**Real-world Defense:** Network-level packet filtering, Anycast CDN networks (like Cloudflare), and dedicated scrubbing centers.
**SentinelAPI Approach:** Heuristic-based (Application Layer). Tracks requests per authenticated user and IP. At 50 requests within 10 seconds, that scope receives HTTP 429 for 30 seconds. Each simulation scenario has separate state.

### 8. Server-Side Request Forgery (SSRF)
**What it is:** Attackers trick the server into making an outbound HTTP request to an internal network target (like a local database or cloud metadata service) that the attacker couldn't reach directly.
**Real-world Defense:** Strict allow-listing of destination URLs, DNS resolution checks before fetching, and disabling access to `169.254.169.254`.
**SentinelAPI Approach:** Signature/Heuristic-based. Parses the requested `url` parameter and blocks requests attempting to resolve to `localhost`, private subnets (10.x.x.x), or the AWS/cloud metadata IP.

### 9. Malicious File Upload
**What it is:** Attackers upload malicious executable files or scripts disguised as harmless images (e.g., renaming `shell.php` to `image.png`) to achieve Remote Code Execution.
**Real-world Defense:** Storing uploads outside the web root, using a separate domain for serving user content, and deep inspection/re-encoding of files.
**SentinelAPI Approach:** Signature-based. Reads the raw buffer of the uploaded file to check its "magic bytes" (file signature). For example, it checks if the buffer starts with `4D 5A` (MZ) indicating a Windows Executable.

### 10. Scanner / Attack Tool Signature
**What it is:** Attackers use automated vulnerability scanners (like sqlmap, Nikto, or DirBuster) to map out the application and discover flaws quickly.
**Real-world Defense:** WAFs that maintain up-to-date threat intelligence databases of known bad IPs and tool signatures.
**SentinelAPI Approach:** Signature-based. Inspects the `User-Agent` HTTP header for hardcoded substrings associated with popular penetration testing tools.

### 11. Endpoint Enumeration
**What it is:** Attackers guess or brute-force hidden directories, admin panels, or backup files by requesting thousands of paths and seeing which ones return a 200 OK versus a 404 Not Found.
**Real-world Defense:** Rate-limiting based on 404 ratios, deploying honeypot endpoints, and monitoring anomalous browsing behavior.
**SentinelAPI Approach:** Heuristic-based. Counts lab routes that will produce 404 responses and stores the threshold alert before returning the response. If an IP generates 15 or more 404s within 20 seconds, it is flagged for scanning behavior.

## Repeatable experiments and evidence

The Simulation Lab and CLI share one server-side runner. The standard profile contains 175 HTTP checks across 11 detector families and benign controls, including a real 31-second cooldown recovery check. Every positive case verifies HTTP status and a matching alert row linked by simulation/case ID. Negative controls verify both a successful response and no alert. Reports retain request inputs with passwords redacted, expected/actual status, detector attribution, alert IDs, latency, and per-scenario totals.

The extended profile adds 120 raw SQL/XSS probes from SecLists revision ab068333d7d44a9376e2037b0ed7d2e8ca5c6610. Source and license are bundled in attack-sim/fixtures/. Raw probes can depend on a different injection context. An allowed probe indicates a signature coverage gap, not a proven exploitable vulnerability. The lab never executes submitted SQL/shell commands, renders submitted HTML, or fetches supplied URLs.

Runs persist in PostgreSQL and export as JSON, CSV, and HTML. Administrators can view all runs; analysts and viewers see only their own reports. Viewers cannot start experiments. Cancellation and interrupted runs remain visible in history.

See README.md for all startup, dictionary, injection, flood, export, and verification commands.
