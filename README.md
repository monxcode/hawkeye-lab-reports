[![Verify Lab](https://img.shields.io/badge/Verify%20Lab-CyberDefenders-00B8D4?style=for-the-badge&logo=github&logoColor=white)](https://cyberdefenders.org/blueteam-ctf-challenges/achievements/mohan_singh_parmar/hawkeye/)

# HawkEye Lab Reports

A forensic network-analysis exercise reconstructing a real-world information-stealer infection from a single packet capture (`![stealer.pcap](/src-data/stealer.pcap)`), documented through independent Red Team, Blue Team, and Purple Team reports.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Repository Structure](#repository-structure)
3. [Objectives](#objectives)
4. [Prerequisites](#prerequisites)
5. [Required Tools](#required-tools)
6. [How to Analyze `pcap/hawkeye.pcap`](#how-to-analyze-pcaphawkeyepcap)
7. [How to Use the Reports](#how-to-use-the-reports)
8. [Skills Demonstrated](#skills-demonstrated)
9. [Learning Outcomes](#learning-outcomes)
10. [References](#references)

---

## Project Overview

HawkEye Lab is a self-contained network-forensics exercise built entirely around one artifact: a packet capture of a Windows domain-joined workstation being infected with an information-stealer, fingerprinting its environment, and exfiltrating data over SMTP. Rather than running a live attacker/defender range, this project works backward from the pcap to reconstruct the full attack chain, then documents it from three complementary perspectives:

- **Red Team** — what the attacker/malware did, phase by phase.
- **Blue Team** — how the activity could have been detected, contained, and remediated.
- **Purple Team** — a correlated attack-vs-defense view with prioritized recommendations.

All findings are grounded in direct `tshark`/Wireshark analysis of `pcap/hawkeye.pcap`. Where the capture does not provide enough evidence to support a claim (e.g., host-side persistence mechanisms, which are not visible on the wire), the reports and artifacts use explicit placeholders rather than invented detail.

---

## Repository Structure

```text
hawkeye-lab-reports/
│
├─ artifacts/
│  ├─ hashes.md
│  └─ indicators.md
│
├─ logs/
│  └─ timeline.md
│
├─ reports/
│  ├─ blue-team-report.md
│  ├─ purple-team-report.md
│  └─ red-team-report.md
│
├─ screenshots/
│  └─ wireshark.png
│
├─ src-data/
│  └─ stealer.pcap
│
├─ LICENSE
│
└─ README.md

```

---

## Objectives

- Reconstruct a full attacker kill chain (delivery, discovery, C2/beaconing, exfiltration) using only network capture data.
- Produce professional, GitHub-ready documentation suitable for a security portfolio, in the format of real-world red/blue/purple team deliverables.
- Extract and document indicators of compromise (IPs, domains, URLs, file hashes) directly from the capture.
- Map observed behavior to the MITRE ATT&CK framework and the Cyber Kill Chain.
- Demonstrate a repeatable methodology for turning a single pcap into a structured incident record.

---

## Prerequisites

- Basic familiarity with TCP/IP networking and common application-layer protocols (HTTP, SMTP, DNS, Kerberos, SMB/LDAP).
- Basic command-line comfort (Linux/macOS/WSL shell).
- Read access to `pcap/hawkeye.pcap` in this repository.
- No prior malware-analysis experience is required; this exercise focuses on network-layer evidence only.

---

## Required Tools

| Tool | Purpose |
|---|---|
| [Wireshark](https://www.wireshark.org/) | GUI-based packet inspection and protocol dissection |
| `tshark` (bundled with Wireshark) | Command-line packet analysis, filtering, and object extraction |
| `capinfos` (bundled with Wireshark) | Capture file metadata and hashing |
| `sha256sum` / `md5sum` / `sha1sum` | Hashing extracted files for IOC documentation and threat-intel lookups |
| A text editor / Markdown viewer | Reviewing and editing the reports in this repository |

---

## How to Analyze `pcap/hawkeye.pcap`

The following commands reproduce the core analysis steps used to produce the reports in this repository.

#### 1. Capture summary and hashing
```bash
capinfos pcap/hawkeye.pcap
```
 
#### 2. Protocol hierarchy overview
```bash
tshark -r pcap/hawkeye.pcap -q -z io,phs
```
 
#### 3. Top-level IP conversations
```bash
tshark -r pcap/hawkeye.pcap -q -z conv,ip
```
 
#### 4. DNS queries (identify contacted domains)
```bash
tshark -r pcap/hawkeye.pcap -Y "dns.flags.response==0" -T fields \
  -e frame.time -e ip.src -e dns.qry.name
```
 
#### 5. HTTP requests (identify payload delivery and beacon traffic)
```bash
tshark -r pcap/hawkeye.pcap -Y http.request -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.host \
  -e http.request.method -e http.request.uri -e http.user_agent
```
 
#### 6. Extract any files transferred over HTTP
```bash
mkdir -p extracted
tshark -r pcap/hawkeye.pcap --export-objects http,extracted
```
 
#### 7. Hash any extracted files for IOC documentation
```bash
sha256sum extracted/*
md5sum extracted/*
sha1sum extracted/*
```
 
#### 8. SMTP session review (identify exfiltration activity)
```bash
tshark -r pcap/hawkeye.pcap -Y smtp -T fields \
  -e frame.time -e ip.src -e ip.dst -e smtp.req.command -e smtp.req.parameter
```
 
#### 9. Decode any base64 SMTP AUTH LOGIN credentials observed in step 8
```bash
echo "<base64-string>" | base64 -d
```

Suggested workflow:

1. Start with `capinfos` and the protocol hierarchy to understand capture scope and duration.
2. Use IP conversations and DNS queries to map internal hosts to external infrastructure.
3. Extract and hash any transferred files immediately — these hashes anchor the entire IOC set.
4. Walk HTTP and SMTP traffic chronologically to build the incident timeline.
5. Cross-reference findings against [`logs/timeline.md`](logs/timeline.md), [`artifacts/indicators.md`](artifacts/indicators.md), and [`artifacts/hashes.md`](artifacts/hashes.md) as you go.

---

## How to Use the Reports

| Document | Audience / Use Case |
|---|---|
| [`reports/red-team-report.md`](reports/red-team-report.md) | Understand the attacker's actions, phase by phase, using kill-chain terminology |
| [`reports/blue-team-report.md`](reports/blue-team-report.md) | Understand detection, containment, eradication, and recovery from a SOC perspective |
| [`reports/purple-team-report.md`](reports/purple-team-report.md) | See attacker technique mapped directly to detection/mitigation, with prioritized remediation |
| [`logs/timeline.md`](logs/timeline.md) | Quick chronological reference for the entire incident |
| [`artifacts/indicators.md`](artifacts/indicators.md) | Copy-paste-ready IOC tables for blocklists, SIEM watchlists, or threat-intel platforms |
| [`artifacts/hashes.md`](artifacts/hashes.md) | File hash reference for AV/EDR signature creation and threat-intel lookups |
| `screenshots/` | Supporting visual evidence, organized by report (populate with your own Wireshark/tooling screenshots) |

Recommended reading order: **Red Team Report → Blue Team Report → Purple Team Report → `logs/timeline.md` → `artifacts/`**.

---

## Skills Demonstrated

- Network packet capture analysis using `tshark` and Wireshark.
- Attacker kill-chain and MITRE ATT&CK mapping from raw network evidence.
- SOC-style incident documentation (detection, containment, eradication, recovery).
- Purple-team methodology: correlating offensive technique to defensive control.
- Indicator-of-compromise extraction, hashing, and structured documentation.
- Professional security report writing in GitHub-flavored Markdown.

---

## Learning Outcomes

By working through this repository, a learner should be able to:

- Independently extract IOCs (IPs, domains, URLs, hashes) from an unfamiliar pcap.
- Distinguish legitimate domain/enterprise traffic (Kerberos, SMB, LDAP) from malicious activity within a mixed capture.
- Recognize common commodity-malware behavioral patterns, such as fixed-interval beaconing and protocol-based exfiltration (e.g., SMTP).
- Translate raw technical findings into structured, audience-appropriate reports (red team, blue team, and purple team formats).
- Apply the MITRE ATT&CK framework and Cyber Kill Chain model to real traffic rather than only in the abstract.

---

## References

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [`tshark` Manual Page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- Companion documents: [`reports/red-team-report.md`](reports/red-team-report.md), [`reports/blue-team-report.md`](reports/blue-team-report.md), [`reports/purple-team-report.md`](reports/purple-team-report.md)