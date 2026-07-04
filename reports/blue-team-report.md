# Blue Team Report

## Cover Information

| Field | Detail |
|---|---|
| Project | HawkEye Lab Analysis |
| Author | Mohan Singh Parmar |
| Version | 1.0 |
| Date | 2026-07-04 |
| Classification | Internal / Portfolio Use |
| Source Evidence | `stealer.pcap` (4,003 packets, 2019-04-10 20:37:07 – 21:40:48 UTC) |

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Incident Overview](#incident-overview)
3. [Incident Identification](#incident-identification)
4. [Detection Process](#detection-process)
5. [Indicators of Compromise](#indicators-of-compromise)
6. [Log Analysis](#log-analysis)
7. [Incident Timeline](#incident-timeline)
8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
9. [Detection Opportunities](#detection-opportunities)
10. [Containment](#containment)
11. [Eradication](#eradication)
12. [Recovery](#recovery)
13. [Monitoring Recommendations](#monitoring-recommendations)
14. [Security Improvements](#security-improvements)
15. [Lessons Learned](#lessons-learned)
16. [Conclusion](#conclusion)
17. [References](#references)

---

## Executive Summary

On 2019-04-10, host `Beijing-5cd1-PC` (`10.4.10.132`), a member of the `pizzajukebox.com` Active Directory domain, was infected with a Windows information-stealer after downloading an executable (`tkraw_Protected99.exe`) from an external HTTP server. Once resident, the malware performed recurring "what is my IP" beacon checks and exfiltrated data via automated SMTP sessions to an attacker-controlled mailbox roughly every ten minutes. This report documents the incident from a SOC/defensive perspective: how it could have been detected, the associated indicators of compromise, and the containment, eradication, and monitoring improvements recommended as a result.

---

## Incident Overview

From a SOC perspective, this incident would most plausibly first surface as one or more of the following alerts, had the relevant detections been in place at the time:

- A proxy/firewall alert for an executable download from an uncategorized or newly observed domain (`proforma-invoices.com`).
- A DLP or egress-filtering alert for outbound SMTP (TCP/25) traffic originating from a non-mail-server endpoint.
- A threat-intelligence match on the destination IP `66.171.248.178` (`bot.whatismyipaddress.com`) or the SMTP server `23.229.162.69`, if either had prior reputation data.
- A UEBA/behavioral alert for a workstation making periodic, machine-generated HTTP requests at a fixed interval — a classic beacon signature.

None of the above alerting is confirmed to have fired in this specific case; this section describes the *detection opportunities* the incident should have generated.

---

## Incident Identification

| Attribute | Value |
|---|---|
| Affected host | `Beijing-5cd1-PC` (`10.4.10.132`) |
| Domain | `pizzajukebox.com` |
| Domain Controller | `PizzaJukebox-DC` (`10.4.10.4`) |
| Malicious file | `tkraw_Protected99.exe` |
| Delivery source | `proforma-invoices.com` (`217.182.138.150`) |
| Exfiltration destination | SMTP server `23.229.162.69:25` |
| Exfil account/domain | `sales.del@macwinlogistics.in` |
| Beacon destination | `bot.whatismyipaddress.com` (`66.171.248.178`) |
| First observed malicious activity | 2019-04-10 20:37:54 UTC (malware download) |
| Classification | Information stealer / credential exfiltration |

---

## Detection Process

**SIEM**

Replace this section with your actual HawkEye Lab SIEM platform and specific detection rule names/IDs used to alert on this activity.

**IDS/IPS**

A network IDS with an up-to-date ruleset (e.g., Suricata/Snort with ET Open or a commercial feed) should have flagged:

- The HTTP download of a Windows PE executable from a domain with no prior reputation, particularly given the mismatched/outdated `MSIE 7.0` user-agent string.
- SMTP `AUTH LOGIN` traffic originating from a workstation IP rather than an approved mail relay/gateway.

**Firewall**

Egress filtering logs would show:

- Repeated outbound TCP/80 connections from `10.4.10.132` to `66.171.248.178` at ~10 minute intervals.
- Repeated outbound TCP/25 connections from `10.4.10.132` to `23.229.162.69`, which should be unusual if the firewall policy restricts direct SMTP egress to an approved mail relay only.

**Endpoint / Antivirus**

Host-based AV/EDR should be checked for:

- Detection or quarantine events for the SHA256 `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11` / MD5 `71826ba081e303866ce2a2534491a2f7`.
- Process creation and network-connection telemetry correlating `tkraw_Protected99.exe` (or its in-memory/renamed process) to the outbound HTTP and SMTP connections identified in this pcap.

Replace this subsection with actual AV/EDR console findings if available from your HawkEye Lab environment; this pcap alone cannot confirm host-side detection status.

**Windows Logs**

Relevant Windows Event Log sources to review on `Beijing-5cd1-PC`:

- Security Event ID 4688 (process creation) around 20:37:54 UTC for execution of the downloaded file.
- Sysmon Event ID 1 (process creation), Event ID 3 (network connection) for correlating the beacon and SMTP sessions to a specific process.
- Sysmon Event ID 11/23 (file creation) for the dropped executable.

**Linux Logs**

Not applicable to the victim host in this capture (Windows workstation); however, if the SMTP relay or web proxy logs are hosted on Linux infrastructure, review `/var/log/squid` (or equivalent) and mail relay logs for corroborating entries.

---

## Indicators of Compromise

**IP Addresses**

| IP | Role |
|---|---|
| `217.182.138.150` | Malware delivery host (`proforma-invoices.com`) |
| `66.171.248.178` | Beacon/recon destination (`bot.whatismyipaddress.com`) |
| `23.229.162.69` | Exfiltration SMTP server |
| `10.4.10.132` | Infected internal host (`Beijing-5cd1-PC`) |
| `10.4.10.4` | Internal Domain Controller (`PizzaJukebox-DC`) — legitimate, not an IOC |

**Domains**

| Domain | Role |
|---|---|
| `proforma-invoices.com` | Malware hosting/delivery |
| `macwinlogistics.in` | Exfiltration mailbox domain |
| `bot.whatismyipaddress.com` | Third-party IP-check service abused for recon |

**URLs**

| URL | Role |
|---|---|
| `http://proforma-invoices.com/proforma/tkraw_Protected99.exe` | Malicious payload delivery URL |

**File Names / Hashes**

| Attribute | Value |
|---|---|
| File name | `tkraw_Protected99.exe` |
| File size | 2,025,472 bytes |
| MD5 | `71826ba081e303866ce2a2534491a2f7` |
| SHA256 | `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11` |

**Processes**

Replace this section with the actual process name/PID confirmed via endpoint telemetry (Sysmon/EDR) to have made the outbound connections; not derivable from network capture alone.

**Registry Keys**

Replace this section with any persistence-related registry keys (e.g., `Run`/`RunOnce` keys) identified via host forensics; no registry activity is visible in a network capture.

**User Accounts**

| Account | Context |
|---|---|
| `beijing-5cd1-pc$` | Domain computer account used for Kerberos authentication (legitimate) |
| `sales.del@macwinlogistics.in` | Attacker-controlled SMTP account used for exfiltration `AUTH LOGIN` and as the mail envelope sender/recipient |

---

## Log Analysis

**Authentication Logs**

The only authentication activity visible is legitimate Kerberos AS-REQ/AS-REP and TGS-REQ/TGS-REP exchanges between `10.4.10.132` and the Domain Controller, consistent with normal domain logon/service-ticket behavior. No anomalous authentication (e.g., unusual logon type, off-hours interactive logon) is evidenced in this capture.

**Event Logs**

Correlate the timestamps in this report against local Windows Security and Sysmon event logs on `Beijing-5cd1-PC`, which were not part of this capture.

**Firewall Logs**

Cross-reference perimeter firewall/proxy logs for the destination IPs/domains listed under Indicators of Compromise to confirm allow/deny decisions at the time of the incident and to search for other internal hosts contacting the same infrastructure.

**Syslogs**

Replace this section with relevant syslog entries from network infrastructure (DNS resolvers, mail relays) if centralized logging was in place for this HawkEye Lab environment.

**Web Logs**

If a web/HTTP proxy was in place, its logs should show the `GET /proforma/tkraw_Protected99.exe` request and the recurring `GET /` requests to `bot.whatismyipaddress.com`; these are currently only confirmed via the pcap itself.

---

## Incident Timeline

| Time (UTC) | Event |
|---|---|
| 20:37:54 | Malicious executable `tkraw_Protected99.exe` downloaded via HTTP from `proforma-invoices.com` |
| 20:38:15 | First beacon/recon `GET /` request to `bot.whatismyipaddress.com` |
| 20:38:16 | First SMTP exfiltration session established to `23.229.162.69:25` |
| 20:48:20 | Second beacon and SMTP exfiltration cycle |
| 20:58:24 | Third beacon and SMTP exfiltration cycle |
| 21:08:30 | Fourth beacon (`bot.whatismyipaddress.com`) |
| 21:18:34 | Fifth beacon (`bot.whatismyipaddress.com`) |
| 21:28:38 | Beacon and SMTP exfiltration cycle |
| 21:38:42 | Final beacon and SMTP exfiltration cycle observed in capture |
| 21:40:48 | Capture ends; incident status at this point unresolved/ongoing |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Initial Access | T1189 – Drive-by Compromise / T1566 – Phishing (inferred) | Executable delivered via HTTP from a lure-themed domain; the initiating email/link itself is not present in this capture but is the most likely delivery vector |
| Execution | T1204.002 – User Execution: Malicious File | Downloaded `.exe` presumed executed by the user or a script, based on subsequent malicious network activity |
| Discovery | T1016 – System Network Configuration Discovery | Recurring queries to a public "what is my IP" service to fingerprint the victim's external address |
| Command and Control | T1071.001 – Application Layer Protocol: Web Protocols | Use of standard HTTP for beacon/check-in traffic |
| Exfiltration | T1048.003 – Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Use of SMTP to exfiltrate data to an attacker-controlled mailbox |
| Collection (inferred) | T1056 – Input Capture / T1113 – Screen Capture | Not directly observable in network traffic, but consistent with the known behavior of information-stealer/keylogger malware families using this delivery-and-SMTP-exfil pattern |

---

## Detection Opportunities

1. **New/rare domain executable download** — alert on any `.exe`/`.dll`/script download from a domain with no established reputation or first-seen within the last N days.
2. **Fixed-interval beaconing** — alert on any internal host making outbound HTTP requests to the same external host at a highly regular interval (here, ~10 minutes) over a sustained period.
3. **Direct SMTP egress from non-mail-infrastructure hosts** — alert (or block) any workstation-originated TCP/25 connection that does not traverse the approved internal mail relay.
4. **User-Agent anomaly** — alert on HTTP requests using outdated/inconsistent user-agent strings (e.g., `MSIE 7.0` from a host whose other traffic indicates a modern OS/browser).
5. **DNS-based detection** — alert on DNS queries for `macwinlogistics.in` or other domains matching known infostealer exfiltration infrastructure once added to threat-intel feeds.

---

## Containment

1. Immediately isolate `Beijing-5cd1-PC` from the network (NAC quarantine VLAN or switch port disable) to stop further exfiltration.
2. Block outbound traffic to `217.182.138.150`, `66.171.248.178`, and `23.229.162.69` at the perimeter firewall.
3. Block DNS resolution for `proforma-invoices.com`, `macwinlogistics.in`, and any related infrastructure via DNS sinkhole/RPZ.
4. Preserve full volatile memory and disk image of the affected host before remediation for forensic completeness.

---

## Eradication

1. Remove the malicious executable and any dropped/persistence artifacts from `Beijing-5cd1-PC` (reimage is strongly preferred over manual cleanup for commodity stealer malware).
2. Rotate credentials for any accounts that may have been captured (local Windows account, browser-stored credentials, and any credentials typed on the host during the infection window).
3. Revoke and reissue Kerberos tickets / force password reset for the computer account if domain-integrity concerns are identified during host forensics.
4. Confirm removal via a full AV/EDR scan and hash-based verification against `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11`.

---

## Recovery

1. Reimage and rejoin `Beijing-5cd1-PC` to the domain from a known-good, patched baseline image.
2. Monitor the host closely (enhanced logging/EDR sensitivity) for 30 days post-recovery for any reinfection indicators.
3. Notify affected users to change passwords for any personal or business accounts accessed from the infected host during the compromise window.
4. Conduct a review of any business email/financial transactions the user may have initiated during the infection period, given the "invoice"-themed lure filename suggests possible Business Email Compromise (BEC) targeting.

---

## Monitoring Recommendations

- Deploy egress filtering rules restricting SMTP (TCP/25) from all endpoints except the approved mail relay.
- Add the IOCs identified in this report to SIEM watchlists and threat-intelligence platform (TIP) feeds.
- Implement beacon-detection analytics (regular-interval outbound connection detection) in the SIEM/NDR platform.
- Enable full HTTP object logging/extraction on the web proxy for retrospective analysis of future incidents.
- Enable Sysmon (or equivalent EDR telemetry) fleet-wide, at minimum for process creation (Event ID 1) and network connection (Event ID 3) logging.

---

## Security Improvements

1. Implement application allow-listing to prevent unapproved executables from running on end-user workstations.
2. Deploy web/email gateway sandboxing to detonate suspicious attachments/downloads before delivery to the user.
3. Enforce SMTP egress control at the firewall (block direct outbound TCP/25 from all non-relay hosts).
4. Expand user security-awareness training to cover invoice-themed phishing lures specifically.
5. Integrate threat-intelligence feeds for newly registered/low-reputation domains into the web proxy and DNS filtering layer.

---

## Lessons Learned

- The absence of SMTP egress restrictions allowed a single infected workstation to directly exfiltrate data to an external mail server, bypassing any DLP or content inspection that would normally sit on the corporate mail gateway.
- Regular-interval beacon traffic, even over benign-looking protocols (plain HTTP `GET /`), is a highly reliable behavioral indicator that should be a standard detection rule regardless of payload content.
- Full packet capture proved sufficient to reconstruct the entire incident timeline in the absence of endpoint telemetry, reinforcing the value of network-level visibility as a compensating control.

---

## Conclusion

This incident reflects a common but serious information-stealer compromise: a single user-driven executable download led to sustained, automated data exfiltration via SMTP over more than an hour of observed traffic. The absence of egress controls on SMTP and executable downloads were the primary contributing gaps. Implementing the containment, eradication, and monitoring recommendations in this report — particularly SMTP egress restriction and beacon-detection analytics — would have significantly reduced both the likelihood and impact of this incident.

---

## References

- MITRE ATT&CK Framework: <https://attack.mitre.org/>
- Wireshark/`tshark` documentation: <https://www.wireshark.org/docs/>
- Replace this section with internal SOC runbooks, threat-intel platform links, or additional HawkEye Lab reference material used during this investigation.