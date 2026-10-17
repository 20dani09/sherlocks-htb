# WhaleSecret

## Overview

**WhaleSecret** is a Hack The Box Sherlock investigating the compromise of an internal web application deployed with Docker. The provided evidence consists of a Linux UAC triage acquisition and a copy of Apache Superset's SQL Lab cached query results.

The investigation establishes that the attacker accessed Apache Superset 2.0.0, enumerated its database connections, queried sensitive application metadata, and **successfully executed operating-system commands through PostgreSQL**. A later attempt to establish a reverse shell used a malicious Python pickle stored in Superset's `key_value` table and triggered through a dashboard permalink.

The most distinctive finding is an **artifact-to-source-code correlation** with the public [jakabakos Apache Superset exploit](https://github.com/jakabakos/CVE-2023-27524-Apache-Superset-Auth-Bypass-and-RCE): its function flow, endpoint sequence, SQL query strings, and pickle technique closely match the observed evidence. This strongly suggests reuse of that PoC or closely derived code; it does **not** identify an exact script binary or prove a successful reverse shell.

> All timestamps in this write-up are UTC. This is an isolated training environment, and the listed addresses are private lab addresses.

---

## Environment and evidence

| Item | Observed value | Source |
|---|---|---|
| Web application | Apache Superset 2.0.0 | Docker image inventory |
| Vulnerable service | `192.168.194.128:8088` | Host `ip_addr_show.txt` and Docker port mapping |
| Source of suspicious traffic | `192.168.194.129` | Superset web container logs |
| Web container | `superset_app` / `dee3f31ac261` | `docker_container_ls_--all_--size.txt` |
| Database container | `superset_db` / PostgreSQL 10 | Docker image inventory |
| Supporting services | Redis, Superset worker, worker beat, init | Docker image inventory |
| Suspicious requests | 414 from `192.168.194.129` | Superset HTTP logs |
| Exploit-associated User-Agent | `python-requests/2.26.0` (246 requests) | Superset HTTP logs |
| Other observed attacker-side tooling | Firefox, curl, Nmap NSE | Superset HTTP logs |

### Principal evidence paths

- `uac-superset-linux-20251101213209/live_response/network/ip_addr_show.txt`
- `uac-superset-linux-20251101213209/live_response/containers/docker_container_ls_--all_--size.txt`
- `uac-superset-linux-20251101213209/live_response/containers/docker_container_logs_dee3f31ac261.txt`
- `uac-superset-linux-20251101213209/live_response/containers/docker_top_*.txt`
- `uac-superset-linux-20251101213209/live_response/network/ss_-tanp.txt`
- `sqllab/sqllab_copy/` (23 collected cache files; 22 parsed successfully by the pickletools/zlib/msgpack workflow used in this investigation)

The encrypted source archive is intentionally **not** committed to this repository; it may contain credentials, hashes, and other sensitive database contents.

---

## Vulnerabilities and attack path

1. **CVE-2023-27524 — session validation / default SECRET_KEY.** Versions through Superset 2.0.1 using a supplied default `SECRET_KEY` permit unauthorized session forgery. The attacker accessed `/login/`, then obtained an authenticated-looking session and made administrative API requests. The actual session cookie and secret were not captured in HTTP access logs, so cookie forgery is inferred from the exploit sequence, not directly proven.
2. **SQL Lab / PostgreSQL command execution.** With high-privilege access to the metadata database, the attacker retrieved sensitive metadata and executed `COPY ... FROM PROGRAM` statements. The SQL Lab records prove these statements returned `success`.
3. **CVE-2023-37941 — unsafe deserialization of metadata.** The attacker wrote a hex-encoded malicious pickle into `key_value` and requested a dashboard permalink, consistent with a known Superset deserialization-to-RCE technique. The permalink request returned HTTP 500. This documents an attempted trigger, but not a proven callback or established shell.

The attacker-controlled payload attempted a callback to `192.168.194.129:4242` using `/bin/sh -i`.

**Confirmed compromise level:** privileged application/database access and OS command execution in the PostgreSQL environment. **Not confirmed:** successful reverse shell, persistent foothold, lateral movement, or network exfiltration.

---

## Reconstructed attack

| UTC time (2025-11-01) | Observed activity | Interpretation |
|---|---|---|
| 19:24:02–19:24:47 | Browser visits `/login/`; repeated login POSTs return redirects back to login | Initial access attempts |
| 19:25:23–19:25:43 | curl and Nmap NSE requests | Service reconnaissance |
| 19:26:14 | First `python-requests/2.26.0` GET to `/login/` | First logged exploit-script activity (HTB answer) |
| 19:26:17–19:26:32 | Requests to `/login/` redirect; `/superset/welcome/` returns 200 | Consistent with authentication established |
| 19:27:20–19:27:21 | `GET /api/v1/database/{1..100}`; PUT updates; POST creates a database connection | Database enumeration and configuration |
| 19:27:22 | `select username,password from ab_user;` succeeds (2 rows) | User credential-hash query |
| 19:27:30 | `select database_name,sqlalchemy_uri,password from dbs;` succeeds (2 rows) | Database connection information query |
| 19:27:41–19:27:42 | `COPY cmd_exec FROM PROGRAM 'ls /etc/passwd'` succeeds | First observed OS command. **HTB-validated flag:** `2025-11-01 19:27:42` |
| 19:28:10 | `COPY cmd_exec FROM PROGRAM 'cat /etc/passwd'` succeeds (20 result rows) | File-content reconnaissance on database host |
| 19:28:38 | POST dashboard permalink → 201; SQL writes pickle to `key_value` → success | Prepares deserialization attempt |
| 19:28:55 | GET `/superset/dashboard/p/Px38M35XJNG/` → 500 | Attempted activation; outcome unknown |

**Timing note:** the SQL Lab cache records the first `COPY` query starting at `19:27:41.502322 UTC` and ending at `19:27:41.686654 UTC`. The challenge accepted `19:27:42` as the flag, likely from a different event time or rounding. Both values are preserved rather than silently treating them as identical.

The full [timeline](./timeline.md) provides evidence references and confidence notes.

---

## SQL Lab: the decisive artifacts

The query-cache files preserve SQL submitted by the attacker even though the HTTP access logs do not include request bodies.

| Cache file (name prefix) | SQL or behavior | Status |
|---|---|---|
| `6149f044...` | `select username,password from ab_user;` | Success; 2 rows |
| `be9e66df...` | `select database_name,sqlalchemy_uri,password from dbs;` | Success; 2 rows |
| `bdac928d...` | `COPY cmd_exec FROM PROGRAM 'ls /etc/passwd'` | Success; 1 row |
| `c2cf7939...` | `COPY cmd_exec FROM PROGRAM 'cat /etc/passwd'` | Success; 20 rows |
| `83c27445...` | `update key_value set value='\x...'` carrying a protocol-0 pickle | Success; 0 result rows |

The pickle resolves to a reference to `posix.system` and an embedded Python command that opens a TCP connection to `192.168.194.129:4242`, duplicates the socket onto standard input/output/error, and launches an interactive `/bin/sh`. No extracted pickle was executed during analysis.

> `status: success` is evidence that the SQL query completed. It does **not** prove that a subsequently stored pickle was deserialized or that the reverse-shell connection worked.

---

## Exploit-source correlation

The [PoC correlation](./exploit-correlation.md) maps observed activity to individual functions of the public script, including:

- `get_session_cookie`, `crack_session_cookie`, and `forge_session_cookie` — access compatible with cookie forgery;
- `get_superset_metadata_connection` — the 1–100 database-ID enumeration loop;
- `expose_database_in_sqllab` — PUT requests to database configurations;
- credential-harvesting SQL constants — **literal** SQL matches;
- `run_os_command` — **literal** `cmd_exec` / PostgreSQL `COPY FROM PROGRAM` construction;
- `store_new_permalink`, `get_pickle_payload`, `send_pickle_payload`, and `trigger_payload_through_permalink` — permalink/pickle chain.

The combined matches provide strong behavioral attribution to the **PoC family**; exact executable provenance is unproven.

---

## Investigation methodology

The investigation used a read-only workflow: inventory Docker services, identify the web container, count requests by source IP, isolate the malicious session, reconstruct HTTP endpoint sequences, and decode SQL Lab cache files without executing untrusted pickle data.

A simple starting query against the extracted web log:

~~~bash
grep '^192\.168\.194\.129 ' docker_container_logs_dee3f31ac261.txt \
  | grep -E '"(PUT /api/v1/database/|POST /superset/sql_json/|POST /api/v1/dashboard/1/permalink|GET /superset/dashboard/p/)' \
  | awk '{print $4, $6, $7, $9}'
~~~

See [forensic findings and validated flags](./findings.md) for the complete answer set and [PoC correlation](./exploit-correlation.md) for the stronger code-to-artifact comparison.

---

## Assessment and limits

**Established:** administrative-looking access, extensive database enumeration, sensitive SQL queries, PostgreSQL OS-level command execution, and malicious pickle storage.

**Strongly supported but not packet-level verified:** exploit flow is closely derived from the published CVE-2023-27524/CVE-2023-37941 PoC. Access logs alone cannot reveal a forged cookie.

**Unproven:** reverse-shell establishment. No connection to `192.168.194.129:4242` was present in the collected `ss` snapshot, and no matching shell process was present in collected `docker top` snapshots. Those artifacts are point-in-time observations and cannot rule out a short-lived session.

### Defensive takeaways

- Upgrade Apache Superset to a version that fixes both vulnerabilities; rotate all default/compromised Flask session keys.
- Restrict SQL Lab and metadata-database write access; review database roles with privileges to execute `COPY FROM PROGRAM`.
- Investigate requests that enumerate API object IDs followed by configuration writes and repeated `/superset/sql_json/` calls.
- Alert on metadata `key_value` updates with serialized objects, suspicious permalink access, and unusual callback connections from web/database containers.
- Rotate affected credentials if exposure is suspected; the cache shows queries for user hashes and connection information.

### References

- [Apache Superset: CVEs fixed by release](https://superset.apache.org/docs/security/cves/)
- [CVE-2023-27524 — Horizon3.ai PoC](https://github.com/horizon3ai/CVE-2023-27524)
- [jakabakos — Apache Superset Auth Bypass and RCE](https://github.com/jakabakos/CVE-2023-27524-Apache-Superset-Auth-Bypass-and-RCE)
- [Horizon3.ai — Apache Superset Part II: RCE, Credential Harvesting and More](https://horizon3.ai/attack-research/disclosures/apache-superset-part-ii-rce-credential-harvesting-and-more/)
- [Apache advisory: CVE-2023-37941](https://www.openwall.com/lists/oss-security/2023/09/06/7)

---

**Scope:** This is a reconstruction from the provided HTB lab artifacts. Neither the source archive nor working attack payloads have been added to the public repository.
