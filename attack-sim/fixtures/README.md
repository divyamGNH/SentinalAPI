# Offline test corpora

SecLists source: https://github.com/danielmiessler/SecLists

Pinned revision: `ab068333d7d44a9376e2037b0ed7d2e8ca5c6610`.

`seclists.json` contains:

- First 1,000 nonempty lines from `Passwords/Common-Credentials/10k-most-common.txt`.
- 268 nonempty lines from `Fuzzing/Databases/SQLi/Generic-SQLi.txt`.
- 110 nonempty lines from `Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt`.

Copyright/license: see `SECLISTS-LICENSE.txt` (upstream MIT license).

The standard suite uses the common password candidates plus project-authored positive/negative regression cases. The extended suite adds the first 60 SQL and first 60 XSS probes from the pinned files, unmodified. Not all probes form a complete exploit in our lab context: allowed probes are reported as signature coverage gaps, not proven vulnerabilities. There is no shell execution or external fetch in the lab endpoints.

Dictionary attempts are independent trials of up to 25 guesses so a 50-request flood threshold does not hide brute-force detection. Password values never enter saved reports. The separate lab login accepts `admin / password123`; dashboard login uses the real database-backed account and token. The flood test is 60 requests with 10 bounded workers, plus a cooldown rejection and 31-second recovery check, from one machine.
