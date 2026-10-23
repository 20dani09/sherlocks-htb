# Kraken — Network and C2 Assessment

## Executive conclusion

The final recovered PE statically configures **<code>apostlejob3.duckdns.org:2468</code>** as its command-and-control endpoint. A **separate, publicly available ANY.RUN analysis of this exact SHA-256** records the process connecting to **<code>107.172.232.84:2468</code>**.

The victim's AD1 image does **not** independently demonstrate that its local infection established this connection. These are two different evidence sources and must not be conflated.

## 1. Static host and port extraction

After the two AES/GZip layers are unpacked, run:

~~~bash
strings -el payload_1_embedded_unpacked.bin |
  grep -Ei 'duckdns|2468|MasonRAT|MasonGroup'
~~~

Relevant strings:

~~~text
apostlejob3.duckdns.org
2468
MasonRAT
MasonGroup
~~~

Dynamic DNS is relevant because a hostname can resolve to a different IP later. **Do not retrospectively resolve today's address and assume it was the address used in June 2025.**

## 2. External sandbox pivot by exact sample hash

The sample used for enrichment is the recovered final PE with:

~~~text
SHA-256: 9d86ea12e0643cd79f6f97202716d6e7b2a0f2dc81b9255719bb5ca7aaeebd12
SHA-1:   052c0687f023564a3c31fb652bea3405341272cb
~~~

Source: [ANY.RUN — exact matching sample](https://any.run/report/9d86ea12e0643cd79f6f97202716d6e7b2a0f2dc81b9255719bb5ca7aaeebd12/e51a4b2f-a59e-490b-b90f-92abd400e6c5).

In the public report:

- Analysis date: **2026-06-04 20:48:49** (not the original victim incident date).
- File: <code>xxxxxxxxxxxxxxxxxxxxxxxxxxxx.exe</code>.
- SHA-1/SHA-256 match the recovered final PE **exactly**.
- Monitored malicious process: PID <code>6644</code>.
- Malware configuration: <code>apostlejob3.duckdns.org:2468</code>.
- **Connections**: <code>107.172.232.84:2468</code>, domain <code>apostlejob3.duckdns.org</code>.
- **DNS requests**: <code>apostlejob3.duckdns.org -> 107.172.232.84</code>.

The report also identifies the final .NET original filename as <code>MasonClient1.exe</code> and its mutex name as <code>qziZscwy2GgmPKEf</code>.

**Evidence strength:** direct observation in an external sandbox of the exact same bytes. It is **not** direct observation on the original host, and it does not place that connection on the June 2025 victim timeline.

## 3. Victim-side network artifacts examined

The AD1 includes the following records:

| Source | Result / constraint |
|---|---|
| Windows Firewall With Advanced Security event logs | Configuration/security events available; no directly attributable, confirmed RAT-to-C2 connection recovered |
| WFP Operational log | No supporting per-connection event tying the RAT to the C2 recovered |
| NetworkProfile Operational log | Connectivity entries around 14:35 UTC, **before** the identified initial execution |
| Microsoft Edge History SQLite | No browser-navigation evidence of a visit to the C2, but browser history is not a complete record of RAT traffic |
| <code>SRUDB.dat</code> | References to executable resource usage; insufficient to assign an IP endpoint to the malware |
| PCAP/PCAPNG | No packet capture provided in the examined image |
| DNS Client telemetry | No locally recovered DNS-query event demonstrating this exact malicious hostname resolution |

### Interpretation

A configured C2 address and a successful connection are different propositions. The challenge's narrative describes early containment, consistent with limited available network activity, but the AD1 alone cannot demonstrate **when containment happened** or prove the absolute absence of exfiltration.

Do not phrase a conclusion as “the victim connected to 107.172.232.84” unless a victim-specific artifact actually establishes that fact. A more precise conclusion is:

> The recovered payload contained a C2 domain and port. Independently, an exact-hash sandbox run observed a connection to 107.172.232.84:2468. The local forensic acquisition did not establish a completed connection or data exfiltration on the compromised Windows host.

## 4. Defender-oriented pivots

Search DNS, proxy, EDR, firewall and NetFlow records from the actual affected machine and the incident time range:

- Queries for <code>apostlejob3.duckdns.org</code>.
- Egress to <code>107.172.232.84</code> over TCP port <code>2468</code>, with historical context.
- <code>wscript.exe</code> spawning <code>cmd.exe</code> and hidden PowerShell.
- PowerShell script blocks containing <code>Assembly.Load</code>, AES decryption, GZip and <code>EtwEventWrite</code>.
- New BAT file creation in <code>Startup</code> immediately after scripted execution.

For future incidents, confirm connection success/failure and bytes sent/received using independently timestamped endpoint/network telemetry where available.
