
from .utils import sliding_window


def detect_dos_spikes(df, window_seconds=1, pps_threshold=300):
    findings = []
    ipdf = df[df['src'].notna()]
    for start, end, win in sliding_window(ipdf, window_seconds):
        if win.empty:
            continue
        counts = win.groupby('src').size()
        spikes = counts[counts >= pps_threshold]
        for src, pps in spikes.items():
            findings.append({
                'time_window': f"{start} to {end}",
                'src': src,
                'pps': int(pps),
                'reason': f"High packet rate: {int(pps)} pkt/s from {src}"
            })
    return findings
