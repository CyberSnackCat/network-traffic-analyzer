
from .utils import sliding_window


def detect_arp_spoof(df, window_seconds=60, max_mac_per_ip=1):
    findings = []
    for start, end, win in sliding_window(df, window_seconds):
        w = win[win['proto'] == 'ARP']
        if w.empty:
            continue
        # Map IP -> set(MAC)
        ip_to_macs = {}
        for _, r in w.iterrows():
            ip = str(r.get('arp_psrc', ''))
            mac = str(r.get('arp_hwsrc', ''))
            if ip:
                ip_to_macs.setdefault(ip, set()).add(mac)
        for ip, macs in ip_to_macs.items():
            if len(macs) > max_mac_per_ip:
                findings.append({
                    'time_window': f"{start} to {end}",
                    'ip': ip,
                    'macs': sorted(list(macs)),
                    'reason': f"IP {ip} seen with {len(macs)} different MACs"
                })
    return findings
