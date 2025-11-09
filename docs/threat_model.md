
# Threat Model (Simplified)

## Assumptions
- Monitoring a small home/school network with mixed devices
- No decryption of TLS traffic; we use metadata only

## Adversaries
- Local attacker on LAN (e.g., ARP spoofing)
- Malicious DNS resolver / poisoned cache
- Internet host doing opportunistic scans
- Misconfigured devices causing DoS-like bursts

## Detections mapped
- ARP spoofing → LAN attacker trying MITM
- DNS poisoning → DNS answers flip in short windows / low TTL
- Port scan → Many destination ports from one source
- DoS spike → Very high PPS from a single source

## Gaps
- Encrypted payloads are opaque
- No deep TLS analysis (future work: JA3, cert checks)
- Threshold-based detection can false-positive; tune in `config.yaml`
