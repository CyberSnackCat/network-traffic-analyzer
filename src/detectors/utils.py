
import pandas as pd
from datetime import datetime, timedelta
import math


def load_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # Coerce types where possible
    for col in ["sport", "dport", "length", "arp_op", "dns_ttl"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    # timestamp
    df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
    return df


def sliding_window(df: pd.DataFrame, seconds: int):
    if df.empty:
        return []
    df = df.sort_values('ts')
    start = df['ts'].min()
    end = df['ts'].max()
    cur = start
    while cur <= end:
        win_end = cur + pd.Timedelta(seconds=seconds)
        yield (cur, win_end, df[(df['ts'] >= cur) & (df['ts'] < win_end)])
        cur = win_end


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    n = len(s)
    return -sum((cnt/n) * math.log2(cnt/n) for cnt in c.values())
