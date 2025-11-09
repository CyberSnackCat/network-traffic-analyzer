
from .utils import sliding_window


def detect_dns_poison(df, window_seconds=60, ip_change_threshold=2, min_suspicious_ttl=60):
    findings = []
    wdf = df[df['dns_qname'].notna()]
    if wdf.empty:
        return findings
    for start, end, win in sliding_window(wdf, window_seconds):
        if win.empty:
            continue
        q_to_answers = {}
        q_to_ttls = {}
        for _, r in win.iterrows():
            q = str(r.get('dns_qname', '')).lower()
            ans = str(r.get('dns_an', ''))
            ttl = r.get('dns_ttl')
            if not q:
                continue
            if ans:
                ip_list = [a for a in ans.split(',') if a]
                if ip_list:
                    q_to_answers.setdefault(q, set()).update(ip_list)
                    if ttl and ttl > 0:
                        q_to_ttls.setdefault(q, []).append(ttl)
        for q, answers in q_to_answers.items():
            if len(answers) >= ip_change_threshold:
                ttl_list = q_to_ttls.get(q, [])
                low_ttl = (min(ttl_list) if ttl_list else None)
                findings.append({
                    'time_window': f"{start} to {end}",
                    'query': q,
                    'answers': sorted(list(answers)),
                    'min_ttl_seen': low_ttl,
                    'reason': (
                        f"DNS answers flipped {len(answers)} times"
                        + (f"; low TTL {low_ttl}" if (low_ttl and low_ttl < min_suspicious_ttl) else "")
                    )
                })
    return findings
