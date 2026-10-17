# WhaleSecret — Findings, indicators, and HTB answers

## Validated challenge answers

| Question | Answer | Validation |
|---|---|---|
| What was the IP and port of the vulnerable server? | `192.168.194.128:8088` | `ip_addr_show.txt` and Docker mapping |
| What was the name of the vulnerable software hosted on the system? | `Apache Superset 2.0.0` | `apache/superset:2.0.0` container image |
| What was the IP of the malicious threat actor? | `192.168.194.129` | Superset HTTP source IP |
| What CVE did the malicious actor exploit? | `CVE-2023-27524` | Session-validation vulnerability; behavior strongly matches public PoC |
| What User-Agent did the malicious actor use while exploiting the vulnerability? | `python-requests/2.26.0` | 246 malicious-source requests with this UA |
| At what time did the malicious actor first use the exploit? | `2025-11-01 19:26:14` (UTC) | First observed `python-requests` GET `/login/` |
| At what time was the first system command executed through the exploit? | `2025-11-01 19:27:42` (UTC) | **Accepted by HTB**; SQL cache records query start `19:27:41.502322` |
| What was the first system command executed through the exploit? | `ls /etc/passwd` | `bdac928d5ff607f5a2026c08408a823d` |
| Which port did the reverse shell connect to? | `4242` | Destination in decoded pickle payload |

**Separate vulnerability used in the post-access RCE attempt:** `CVE-2023-37941` (metadata database write / unsafe pickle deserialization). This is different from the challenge answer for the initial bypass.

## Indicators and artifacts

| Category | Indicator | Confidence and context |
|---|---|---|
| Source IP | `192.168.194.129` | High; malicious source in this lab (RFC1918 address) |
| Target service | `192.168.194.128:8088` | High; Superset web service exposed by Docker |
| HTTP User-Agent | `python-requests/2.26.0` | High as observation, low as an independently malicious signature |
| Reverse-shell destination | `192.168.194.129:4242/TCP` | High as **intent** extracted from payload; callback success not verified |
| Enumeration endpoint | `/api/v1/database/{id}`, IDs 1–100 | High; repeated automated sequence |
| SQL endpoint | `/superset/sql_json/` | High; attack SQL executed there |
| Metadata table | `ab_user` | Usernames and password hashes queried |
| Database configuration table | `dbs` | Database connection values queried |
| OS command execution | PostgreSQL `COPY ... FROM PROGRAM` | High; executed successfully |
| Temporary SQL table | `cmd_exec(cmd_output text)` | High; created to collect command output |
| Deserialization target | `key_value` | High; malicious pickle written via SQL |
| Permalink | `/superset/dashboard/p/Px38M35XJNG/` | High; request returned 500 |

**Important:** These are training-environment indicators. The RFC1918 addresses are not global blocklist candidates. Endpoint and SQL patterns are most useful when combined with application, identity, and database context.

## Evidence sufficiency

### Confirmed compromise

The successful `COPY FROM PROGRAM` results demonstrate that commands were executed on the PostgreSQL database host/container. This elevates the incident beyond suspicious logins or ordinary SQL queries.

### Potential credential exposure

Queries for `ab_user.username`, `ab_user.password`, `dbs.sqlalchemy_uri` and `dbs.password` completed and returned rows. The query evidence supports access to credential-related data; it does not establish successful external transfer or password cracking.

### Reverse shell: attempted, not verified

The payload intended to establish a Python socket to `192.168.194.129:4242` and spawn an interactive `/bin/sh`. A permalink was requested after the SQL update and caused HTTP 500. There was no contemporaneous packet capture or validated network telemetry proving a completed TCP connection.

### Initial authentication bypass: strong hypothesis, incomplete direct proof

Requests align with the CVE-2023-27524 exploitation flow, but normal access logs do not capture Flask session cookie bodies or signatures. The cookie-forgery step cannot be independently reconstructed solely from the supplied HTTP text log.

## Recommendations drawn from this case

1. Replace vulnerable Superset versions and rotate the Flask secret key; remove any known defaults.
2. Investigate all accounts and keys accessible through the metadata database and rotate potentially exposed credentials.
3. Reduce database privileges and disallow unnecessarily privileged `COPY FROM PROGRAM` execution.
4. Restrict SQL Lab to appropriate administrators and use audited DB roles; limit connectivity between application components.
5. Monitor `key_value` writes and unexpected dashboard permalink activity, with network telemetry to validate callbacks.
6. Correlate web-layer anomalies with query history and database audit trails rather than relying solely on HTTP status codes.

## Artifact handling

The provided `WhaleSecret.zip` was password-protected. Its contents may include passwords and hashes, so the repository intentionally contains only sanitized descriptions and investigative commands. Neither the decrypted archive nor the raw malicious payload is published.

## Links

- [Main investigation](./README.md)
- [Detailed timeline](./timeline.md)
- [Exploit-source correlation](./exploit-correlation.md)
