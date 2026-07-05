# Indicators of Compromise (IOCs)

This document consolidates all indicators of compromise identified through direct analysis of [`pcap/hawkeye.pcap`](../pcap/hawkeye.pcap), as referenced in the [Red Team](../reports/red-team-report.md), [Blue Team](../reports/blue-team-report.md), and [Purple Team](../reports/purple-team-report.md) reports.

> Indicators without direct network-level evidence (e.g., registry keys, in-memory process names) are marked as placeholders. These require host-based forensics or EDR telemetry not captured in `pcap/hawkeye.pcap` to confirm.

---

## Table of Contents

1. [IP Addresses](#ip-addresses)
2. [Domains](#domains)
3. [URLs](#urls)
4. [Hostnames](#hostnames)
5. [User Accounts](#user-accounts)
6. [File Names](#file-names)
7. [Processes](#processes)
8. [Services](#services)
9. [Registry Keys](#registry-keys)
10. [How These Indicators Were Derived](#how-these-indicators-were-derived)

---

## IP Addresses

| IP Address | Role | Classification | Source |
|---|---|---|---|
| `217.182.138.150` | Malware delivery host (`proforma-invoices.com`) | Malicious | `pcap/hawkeye.pcap` — HTTP GET request |
| `66.171.248.178` | Third-party IP-check service abused for recon/beacon (`bot.whatismyipaddress.com`) | Suspicious (abused legitimate service) | `pcap/hawkeye.pcap` — recurring HTTP GET requests |
| `23.229.162.69` | Exfiltration SMTP server | Malicious | `pcap/hawkeye.pcap` — SMTP session traffic |
| `10.4.10.132` | Infected internal host (`Beijing-5cd1-PC`) | Compromised asset | `pcap/hawkeye.pcap` — all outbound malicious traffic originates here |
| `10.4.10.4` | Internal Domain Controller (`PizzaJukebox-DC`) | Legitimate (not an IOC) | `pcap/hawkeye.pcap` — Kerberos/SMB/LDAP traffic |
| `216.58.193.131` | `update.googleapis.com` (TLS SNI observed) | Legitimate (not an IOC) | `pcap/hawkeye.pcap` — TLS handshake |

---

## Domains

| Domain | Role | Classification | Source |
|---|---|---|---|
| `proforma-invoices.com` | Malware hosting/delivery domain | Malicious | `pcap/hawkeye.pcap` — DNS query and HTTP `Host` header |
| `macwinlogistics.in` | Exfiltration mailbox domain | Malicious | `pcap/hawkeye.pcap` — DNS query preceding each SMTP session; matches SMTP envelope addresses |
| `bot.whatismyipaddress.com` | Third-party IP-check service abused for recon | Suspicious (abused legitimate service) | `pcap/hawkeye.pcap` — DNS query and HTTP `Host` header |
| `dns.msftncsi.com` | Windows network connectivity status check | Legitimate (not an IOC) | `pcap/hawkeye.pcap` — DNS query |
| `update.googleapis.com` | Google service update check | Legitimate (not an IOC) | `pcap/hawkeye.pcap` — TLS SNI |

---

## URLs

| URL | Role | Source |
|---|---|---|
| `http://proforma-invoices.com/proforma/tkraw_Protected99.exe` | Malicious payload delivery URL | `pcap/hawkeye.pcap` — HTTP GET request |
| `http://bot.whatismyipaddress.com/` | Recon/beacon URL (repeated `GET /`) | `pcap/hawkeye.pcap` — recurring HTTP GET requests |

---

## Hostnames

| Hostname | Role | Classification | Source |
|---|---|---|---|
| `Beijing-5cd1-PC` | Infected workstation NetBIOS/DNS hostname | Compromised asset | `pcap/hawkeye.pcap` — NBNS/DNS/Kerberos traffic |
| `PizzaJukebox-DC` | Domain Controller hostname | Legitimate (not an IOC) | `pcap/hawkeye.pcap` — DNS/Kerberos/SMB traffic |

---

## User Accounts

| Account | Context | Classification | Source |
|---|---|---|---|
| `beijing-5cd1-pc$` | Domain computer account used for Kerberos authentication | Legitimate (not an IOC) | `pcap/hawkeye.pcap` — Kerberos AS-REQ/TGS-REQ |
| `sales.del@macwinlogistics.in` | Attacker-controlled SMTP account used for `AUTH LOGIN` and as mail envelope sender/recipient | Malicious | `pcap/hawkeye.pcap` — SMTP `AUTH LOGIN` (base64-decoded), `MAIL FROM`/`RCPT TO` |

---

## File Names

| File Name | Size | Classification | Source |
|---|---|---|---|
| `tkraw_Protected99.exe` | 2,025,472 bytes | Malicious (PE32 executable, GUI, Intel 80386, 5 sections) | `pcap/hawkeye.pcap` — HTTP object export |

For hash values (MD5/SHA1/SHA256) associated with this file, see [`artifacts/hashes.md`](hashes.md).

---

## Processes

| Process Name | PID | Classification | Source |
|---|---|---|---|
| *Placeholder — not observable in network capture* | *Placeholder* | Unknown | Requires Sysmon Event ID 1 (process creation) or EDR telemetry from `Beijing-5cd1-PC`; replace this row with the confirmed process name/PID once host forensics are available |

---

## Services

| Service Name | Role | Classification | Source |
|---|---|---|---|
| *Placeholder — no anomalous service creation observed in network capture* | *Placeholder* | Unknown | Requires Windows Event ID 7045 (service creation) or endpoint audit data; replace this row if a malicious service is confirmed on the host |

---

## Registry Keys

| Registry Key | Purpose | Classification | Source |
|---|---|---|---|
| *Placeholder — not observable in network capture* | *Placeholder (e.g., `Run`/`RunOnce` persistence key)* | Unknown | Requires registry/host forensics on `Beijing-5cd1-PC`; replace this row once a persistence mechanism is confirmed |

---

## How These Indicators Were Derived

All confirmed (non-placeholder) indicators above were extracted directly from `pcap/hawkeye.pcap` using the following method:

#### DNS queries
```bash
tshark -r pcap/hawkeye.pcap -Y "dns.flags.response==0" -T fields \
  -e frame.time -e ip.src -e dns.qry.name
```

#### HTTP requests (domains, URLs, hostnames of hosting infrastructure)
```bash
tshark -r pcap/hawkeye.pcap -Y http.request -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.host \
  -e http.request.method -e http.request.uri -e http.user_agent
```

#### SMTP session detail (accounts, exfiltration domain/mailbox)
```bash
tshark -r pcap/hawkeye.pcap -Y smtp -T fields \
  -e frame.time -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter
```

#### IP conversations (confirming internal vs external hosts)
```bash
tshark -r pcap/hawkeye.pcap -q -z conv,ip
```

See [`README.md`](../README.md#how-to-analyze-pcaphawkeyepcap) for the full analysis workflow, and [`logs/timeline.md`](../logs/timeline.md) for how these indicators map to the incident chronology.