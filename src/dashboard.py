
import base64
from io import BytesIO
from pathlib import Path
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt

from .detectors.utils import load_csv


def _fig_to_base64(fig):
    buf = BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()


def _timeline_plot(df):
    # packets per second over time
    ts = df['ts'].dt.floor('s')
    counts = ts.value_counts().sort_index()
    fig, ax = plt.subplots(figsize=(8,3))
    counts.plot(ax=ax)
    ax.set_title('Packets per second')
    ax.set_xlabel('Time')
    ax.set_ylabel('Packets')
    ax.grid(True, alpha=0.3)
    return _fig_to_base64(fig)


def _top_talkers(df):
    top = df['src'].value_counts().head(10)
    fig, ax = plt.subplots(figsize=(6,3))
    top.plot(kind='barh', ax=ax)
    ax.invert_yaxis()
    ax.set_title('Top talkers (by packets)')
    ax.set_xlabel('Packets')
    return _fig_to_base64(fig)


def _dns_heat(df):
    d = df[df['dns_qname'].notna()]
    if d.empty:
        fig, ax = plt.subplots(figsize=(4,2))
        ax.text(0.5,0.5,'No DNS data', ha='center', va='center')
        return _fig_to_base64(fig)
    by_q = d.groupby('dns_qname').size().sort_values(ascending=False).head(15)
    fig, ax = plt.subplots(figsize=(8,3))
    by_q.plot(kind='bar', ax=ax)
    ax.set_title('Top DNS queries')
    ax.set_ylabel('Count')
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right')
    return _fig_to_base64(fig)


def build_report(csv_path: str, results: dict) -> str:
    df = load_csv(csv_path)
    Path('reports').mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    out = Path('reports') / f"{ts}_report.html"

    charts = {
        'timeline': _timeline_plot(df),
        'top_talkers': _top_talkers(df),
        'dns': _dns_heat(df)
    }

    def section(title, findings):
        if not findings:
            return f"<h3>{title}</h3><p>No findings.</p>"
        rows = "".join(
            f"<tr><td>{i+1}</td><td><pre>{f}</pre></td></tr>" for i, f in enumerate(findings)
        )
        return f"<h3>{title}</h3><table border='1' cellpadding='6'><tr><th>#</th><th>Details</th></tr>{rows}</table>"

    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Traffic Analyzer Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    img {{ max-width: 100%; }}
    table {{ border-collapse: collapse; width: 100%; }}
    pre {{ white-space: pre-wrap; word-break: break-word; }}
  </style>
</head>
<body>
  <h1>Traffic Analyzer Report</h1>
  <p>Input: {csv_path}</p>
  <h2>Overview</h2>
  <img src="data:image/png;base64,{charts['timeline']}" />
  <img src="data:image/png;base64,{charts['top_talkers']}" />
  <img src="data:image/png;base64,{charts['dns']}" />

  <h2>Findings</h2>
  {section('ARP Spoofing', results.get('arp_spoof', []))}
  {section('DNS Poisoning', results.get('dns_poison', []))}
  {section('Port Scans', results.get('port_scans', []))}
  {section('DoS Spikes', results.get('dos_spikes', []))}

  <hr />
  <p>Generated at {datetime.utcnow().isoformat()} UTC</p>
</body>
</html>
"""
    out.write_text(html, encoding='utf-8')
    return str(out)
