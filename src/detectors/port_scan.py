
from .utils import sliding_window


def detect_port_scans(df, window_seconds=60, unique_ports_threshold=30, max_destinations=4):
    findings = []
    ipdf = df[df['proto'].isin(['TCP','UDP'])]
    for start, end, win in sliding_window(ipdf, window_seconds):
        if win.empty:
            continue
        combos = {}
        for _, r in win.iterrows():
            src = str(r.get('src',''))
            dst = str(r.get('dst',''))
            dport = int(r.get('dport') or 0)
            if not src or not dport:
                continue
            combos.setdefault(src, {}).setdefault(dst, set()).add(dport)
        for src, dst_map in combos.items():
            # count unique ports across few destinations
            total_unique = sum(len(ports) for ports in dst_map.values())
            if total_unique >= unique_ports_threshold and len(dst_map) <= max_destinations:
                findings.append({
                    'time_window': f"{start} to {end}",
                    'src': src,
                    'dest_count': len(dst_map),
                    'unique_ports': total_unique,
                    'reason': f"{src} probed {total_unique} ports across {len(dst_map)} hosts"
                })
    return findings
