# File Hashes

This document records cryptographic hashes for the packet capture itself and for any files extracted from [`pcap/hawkeye.pcap`](../pcap/hawkeye.pcap), as referenced in the [Red Team](../reports/red-team-report.md), [Blue Team](../reports/blue-team-report.md), and [Purple Team](../reports/purple-team-report.md) reports.

> If you are working from your own copy of `hawkeye.pcap`, recalculate all hashes locally using the commands in [How to Regenerate These Hashes](#how-to-regenerate-these-hashes) rather than relying solely on the values below, to confirm file integrity in your environment.

---

## Table of Contents

1. [Capture File Hash](#capture-file-hash)
2. [Extracted File Hashes](#extracted-file-hashes)
3. [How to Regenerate These Hashes](#how-to-regenerate-these-hashes)

---

## Capture File Hash

| File | MD5 | SHA1 | SHA256 |
|---|---|---|---|
| `pcap/hawkeye.pcap` | *Placeholder — calculate with `md5sum pcap/hawkeye.pcap`* | *Placeholder — calculate with `sha1sum pcap/hawkeye.pcap`* | *Placeholder — calculate with `sha256sum pcap/hawkeye.pcap`* |

---

## Extracted File Hashes

The following file was recovered from HTTP traffic within the capture using `tshark --export-objects`.

| File Name | Size (bytes) | MD5 | SHA1 | SHA256 |
|---|---|---|---|---|
| `tkraw_Protected99.exe` | 2,025,472 | `71826ba081e303866ce2a2534491a2f7` | *Placeholder — calculate with `sha1sum` after export (see below)* | `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11` |

**File details:**

| Attribute | Value |
|---|---|
| File type | PE32 executable (GUI), Intel 80386, 5 sections |
| Delivery source | `http://proforma-invoices.com/proforma/tkraw_Protected99.exe` |
| Delivery IP | `217.182.138.150` |
| Reference | See [`artifacts/indicators.md`](indicators.md) and [`reports/red-team-report.md`](../reports/red-team-report.md#exploitation) |

> If additional files are extracted from other protocol streams in `hawkeye.pcap` (e.g., SMB file transfers, additional HTTP objects), add a new row to the table above for each file, following the same format.

---

## How to Regenerate These Hashes

#### 1. Hash the capture file itself
```bash
md5sum pcap/hawkeye.pcap
sha1sum pcap/hawkeye.pcap
sha256sum pcap/hawkeye.pcap
```

#### (capinfos also reports SHA256/RIPEMD160/SHA1 automatically)
```bash
capinfos pcap/hawkeye.pcap
```
#### 2. Extract all HTTP-transferred files
```bash
mkdir -p extracted
tshark -r pcap/hawkeye.pcap --export-objects http,extracted
```

#### 3. Hash every extracted file
```bash
md5sum extracted/*
sha1sum extracted/*
sha256sum extracted/*
```

Once regenerated, update the placeholder values above with the confirmed hash output, and cross-reference each hash against:

- Your organization's threat-intelligence platform (TIP)
- Public reputation services (e.g., VirusTotal) — note internal policy on submitting samples externally before doing so
- Endpoint/EDR consoles, to confirm whether the file was previously seen, blocked, or executed on `Beijing-5cd1-PC` or any other host

See [`artifacts/indicators.md`](indicators.md) for the full indicator set associated with this file, and [`logs/timeline.md`](../logs/timeline.md) for when this file was delivered within the incident timeline.