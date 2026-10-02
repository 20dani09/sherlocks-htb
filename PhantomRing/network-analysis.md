# PhantomRing — Network Analysis

## Packet capture setup

Network traffic was observed inside the isolated REMnux lab with:

```bash
sudo tcpdump -i lo -nn -A tcp port 4445
```

The hard-coded C2 address was bound locally to loopback:

```text
192.168.56.1:4445/TCP
```

Because both the malware and the emulated C2 were running on the same REMnux VM, the source and destination IP addresses are both `192.168.56.1`. The client side is distinguished by its ephemeral source port.

---

## Observed TCP handshake

When the malware was launched, `tcpdump` captured the TCP three-way handshake:

```text
192.168.56.1:50958 > 192.168.56.1:4445  SYN
192.168.56.1:4445  > 192.168.56.1:50958 SYN, ACK
192.168.56.1:50958 > 192.168.56.1:4445  ACK
```

At the same time, the malware printed:

```text
[+] Connected to 192.168.56.1:4445
```

This dynamically confirms the C2 endpoint recovered during static analysis.

---

## Session characteristics

| Field | Observed value |
|---|---|
| Protocol | TCP |
| C2 address | `192.168.56.1` |
| C2 port | `4445` |
| Client ephemeral port | `50958` |
| Transport encryption observed | None during the tested session |
| C2 interaction | Plain command/response over the established TCP stream |

The C2 protocol is simple and interactive. Commands such as `me`, `users`, `ps`, `ss`, `get`, `recv`, and `privesc` were sent over the same TCP session and the agent returned plaintext responses.

---

## Important note about the capture

The command used during the lab displayed packets live with `-A`, but did **not** save them to a PCAP file.

For a future run, the equivalent capture can be preserved with:

```bash
sudo tcpdump -i lo -nn -s0 -w phantomring.pcap tcp port 4445
```

A saved PCAP would allow later inspection in Wireshark and make it possible to preserve the full command/response exchange as an analysis artifact.
