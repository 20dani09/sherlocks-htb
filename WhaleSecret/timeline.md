# WhaleSecret — Evidence-based timeline

All times **2025-11-01 UTC**. The source IP is `192.168.194.129` and the web application runs at `192.168.194.128:8088`.

## Chronology

| Time | Event | Evidence | Assessment |
|---|---|---|---|
| 19:24:02 | `GET /` → 302, `GET /superset/welcome/` → 302, `GET /login/` → 200 | `docker_container_logs_dee3f31ac261.txt` | Initial unauthenticated browsing |
| 19:24:34–19:24:44 | Five POST requests to `/login/`, followed each time by a GET of the login page | Same container log | Likely unsuccessful interactive login attempts; redirects alone cannot prove credential failures |
| 19:25:23–19:25:33 | Requests from `curl/8.13.0` | Same container log | Manual command-line reconnaissance |
| 19:25:43 | `Mozilla/5.0 (compatible; Nmap Scripting Engine...)` probes | Same container log | Nmap NSE reconnaissance |
| 19:26:14 | First two observed `python-requests/2.26.0` GETs to `/login/` | Same container log | First observed use of the exploit-associated HTTP client |
| 19:26:17 | `python-requests` GET `/login/` → 302 | Same container log | Compatible with an authenticated/forged-cookie request; cookie unavailable |
| 19:26:32 | Browser GET `/superset/welcome/` → 200 | Same container log | Privileged-looking browsing becomes possible |
| 19:26:36 | Browser GET `/superset/sqllab/` → 200 | Same container log | SQL Lab accessible |
| 19:26:51 | `GET /users/list/` → 200 | Same container log | User enumeration |
| 19:27:11 | `GET /roles/list/` → 200 | Same container log | Role enumeration |
| 19:27:20–19:27:21 | Exploit-associated `GET /api/v1/database/1` through `/100`, PUT `/1` → 200; POST `/api/v1/database/` → 201; PUT `/2` → 200 | Same container log | Database lookup, creation and SQL Lab exposure consistent with public PoC |
| 19:27:21.979–19:27:22.034 | `select username,password from ab_user;` | `sqllab_copy/6149f04486f2349c2f266006f2e14132` | Completed, 2 query result rows |
| 19:27:30.182–19:27:30.233 | `select database_name,sqlalchemy_uri,password from dbs;` | `sqllab_copy/be9e66dfbacd4204ccfc150f4d16478c` | Completed, 2 result rows |
| 19:27:41.502–19:27:41.687 | `COPY cmd_exec FROM PROGRAM 'ls /etc/passwd'` inside DROP/CREATE/COPY/SELECT chain | `sqllab_copy/bdac928d5ff607f5a2026c08408a823d` | Confirmed OS command execution on PostgreSQL host; challenge flag time is 19:27:42 |
| 19:28:10.452–19:28:10.614 | `COPY cmd_exec FROM PROGRAM 'cat /etc/passwd'` | `sqllab_copy/c2cf793951c1fc715adb7f6731e3b254` | Confirmed command; 20 result rows |
| 19:28:33 | PUT `/api/v1/database/1` and `/2` → 200 | Web container log | Database configuration activity precedes the permalink exploit stage |
| 19:28:38 | POST `/api/v1/dashboard/1/permalink` → 201 | Web container log | Dashboard permalink created |
| 19:28:38.671–19:28:38.709 | SQL `update key_value set value='\x...'` (hex-encoded malicious pickle) | `sqllab_copy/83c274455bb91a8a78af7a3a95153c1d` | Malicious object stored, SQL completed |
| 19:28:55 | GET `/superset/dashboard/p/Px38M35XJNG/` → 500 | Web container log | Possible deserialization trigger; execution/callback not established |

## Command-time nuance

The first successful database-host command appears in the cached SQL Lab record with a start time of `2025-11-01 19:27:41.502322 UTC`, and an end time of `19:27:41.686654 UTC`. The HTB challenge accepted **`2025-11-01 19:27:42`**.

Do not modify the source timestamp to force agreement with the answer. The task's accepted answer and the cached query's millisecond timing are separate observations.

## What the evidence does and does not establish

### Confirmed

- Docker exposed Superset 2.0.0 on `192.168.194.128:8088`.
- The attacker-controlled lab address `192.168.194.129` generated 414 web requests.
- A `python-requests/2.26.0` client generated 246 requests.
- SQL Lab successfully returned user/database metadata and executed two PostgreSQL `COPY FROM PROGRAM` command chains.
- A hex-encoded protocol-0 pickle designed to run a reverse-shell command was saved through SQL.
- A permalink was created and later requested.

### Not confirmed

- The exact default Flask `SECRET_KEY` used, or the forged session cookie bytes (not present in the available access logs).
- The precise source copy/commit of the attacker's script.
- Successful outbound TCP connection to `192.168.194.129:4242`.
- A persistent shell, lateral movement, or exfiltration of credential data.

The absence of a connection in a point-in-time `ss` snapshot or of a shell in `docker top` is **not proof of non-execution**.

## Evidence collection note

The cache `query.startDttm` and `query.endDttm` values are Unix time in **milliseconds**. To reconstruct UTC:

~~~python
from datetime import datetime, timezone
timestamp = 1762025261502.322
print(datetime.fromtimestamp(timestamp / 1000, timezone.utc))
# 2025-11-01 19:27:41.502322+00:00
~~~

This timeline omits password hashes and the raw callback payload from the public repository.
