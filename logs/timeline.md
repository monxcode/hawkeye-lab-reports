# Incident Timeline

This timeline consolidates the chronological findings from the [Red Team](../reports/red-team-report.md), [Blue Team](../reports/blue-team-report.md), and [Purple Team](../reports/purple-team-report.md) reports into a single reference table, derived from direct analysis of [`pcap/hawkeye.pcap`](../pcap/hawkeye.pcap).

> All timestamps are in UTC and reflect the timestamps recorded in the packet capture itself. Where an exact time cannot be confirmed from available evidence, `TBD` is used as a placeholder rather than an invented value.

---

## Table of Contents

1. [Capture Metadata](#capture-metadata)
2. [Consolidated Timeline](#consolidated-timeline)
3. [Notes](#notes)

---

## Capture Metadata

| Field | Value |
|---|---|
| Capture file | `pcap/hawkeye.pcap` |
| Capture start | 2019-04-10 20:37:07 UTC |
| Capture end | 2019-04-10 21:40:48 UTC |
| Capture duration | ~63 minutes 41 seconds |
| Total packets | 4,003 |
| Primary internal host | `Beijing-5cd1-PC` (`10.4.10.132`) |
| Domain | `pizzajukebox.com` |
| Domain Controller | `PizzaJukebox-DC` (`10.4.10.4`) |

---

## Consolidated Timeline

| Time (UTC) | Phase | Event | Source | Destination | Evidence |
|---|---|---|---|---|---|
| 20:37:07 | Baseline | Capture window begins; routine Kerberos/AD traffic | `10.4.10.132` | `10.4.10.4` | AS-REQ/AS-REP, TGS-REQ/TGS-REP exchanges |
| 20:37:54 | Delivery | HTTP GET for `/proforma/tkraw_Protected99.exe` | `10.4.10.132` | `217.182.138.150` (`proforma-invoices.com`) | HTTP request/response, object export |
| 20:37:54–20:38:xx | Delivery | Malicious PE32 executable fully transferred (2,025,472 bytes) | `217.182.138.150` | `10.4.10.132` | HTTP object export, file hash |
| TBD | Execution | Downloaded executable presumed executed on host | `10.4.10.132` | — | Inferred from subsequent beacon/exfil traffic; not directly observable in network capture |
| 20:38:15 | Discovery / Beacon | First `GET /` request to IP-check service | `10.4.10.132` | `66.171.248.178` (`bot.whatismyipaddress.com`) | HTTP request |
| 20:38:16 | Exfiltration | First SMTP session: `EHLO` → `AUTH LOGIN` → `MAIL FROM`/`RCPT TO` → `DATA` | `10.4.10.132` | `23.229.162.69:25` | SMTP command stream |
| 20:48:20 | Discovery / Beacon | Second IP-check beacon | `10.4.10.132` | `66.171.248.178` | HTTP request |
| 20:48:20–20:48:21 | Exfiltration | Second SMTP exfiltration cycle | `10.4.10.132` | `23.229.162.69:25` | SMTP command stream |
| 20:58:24 | Discovery / Beacon | Third IP-check beacon | `10.4.10.132` | `66.171.248.178` | HTTP request |
| 20:58:24–20:58:25 | Exfiltration | Third SMTP exfiltration cycle | `10.4.10.132` | `23.229.162.69:25` | SMTP command stream |
| 21:08:30 | Discovery / Beacon | Fourth IP-check beacon | `10.4.10.132` | `66.171.248.178` | HTTP request |
| 21:18:34 | Discovery / Beacon | Fifth IP-check beacon | `10.4.10.132` | `66.171.248.178` | HTTP request |
| 21:28:38 | Discovery / Beacon | Sixth IP-check beacon | `10.4.10.132` | `66.171.248.178` | HTTP request |
| 21:28:38 | Exfiltration | Fourth+ SMTP exfiltration cycle | `10.4.10.132` | `23.229.162.69:25` | SMTP/DNS correlation (`macwinlogistics.in` lookup preceding session) |
| 21:38:42 | Discovery / Beacon | Final observed IP-check beacon in capture | `10.4.10.132` | `66.171.248.178` | HTTP request |
| 21:38:42 | Exfiltration | Final observed SMTP exfiltration cycle in capture | `10.4.10.132` | `23.229.162.69:25` | SMTP command stream |
| 21:40:48 | End of capture | Capture window ends; incident status unresolved/ongoing at time of collection | — | — | Last packet timestamp |
| TBD | Detection | Time of actual SOC/analyst detection (if different from capture collection) | — | — | Replace with actual SOC alert/ticket timestamp |
| TBD | Containment | Time host was isolated from the network | — | — | Replace with actual containment action timestamp |
| TBD | Eradication | Time malware/artifacts were removed and host reimaged | — | — | Replace with actual remediation timestamp |
| TBD | Recovery | Time host was returned to production | — | — | Replace with actual recovery timestamp |

---

## Notes

- The recurring ~10-minute interval between the IP-check beacon and the SMTP exfiltration cycle strongly suggests both behaviors are driven by a single timer/scheduled task within the malware.
- Entries marked `TBD` represent activity that either occurred outside the boundaries of `pcap/hawkeye.pcap` (e.g., initial lure delivery, host-side execution, incident response actions) or that requires corroborating evidence (endpoint logs, SOC ticketing data) not available in this capture. These should be filled in with actual timestamps once that evidence is available.
- For the full technical narrative behind each timeline entry, see the [Red Team Report](../reports/red-team-report.md) (attacker actions) and [Blue Team Report](../reports/blue-team-report.md) (detection and response actions).