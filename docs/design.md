
# Design Notes

**Goal:** Detect a few clear, explainable network threats using packet metadata and common-sense heuristics.

## Architecture
- `capture.py` → writes rows to CSV during live sniffing
- `analyze.py` → loads CSV and runs detectors
- `detectors/*` → individual detection modules
- `dashboard.py` → plots and assembles a static HTML report

## Data Model (CSV fields)
- `ts, src, dst, proto, sport, dport, length`
- ARP extras: `arp_op, arp_psrc, arp_pdst, arp_hwsrc, arp_hwdst`
- DNS extras: `dns_qname, dns_an, dns_ttl`

## Why CSV instead of PCAP
- Easier to inspect and graph with standard tools
- Smaller and simpler for a school project

## Extending
- Add TLS SNI parsing and JA3 fingerprints
- Add HTTP Host / path summaries
- Add a small allowlist for known-safe DNS answers per domain
