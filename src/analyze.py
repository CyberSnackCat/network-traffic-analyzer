
import yaml
from pathlib import Path
from typing import Dict, List
import pandas as pd

from .detectors.utils import load_csv
from .detectors.arp_spoof import detect_arp_spoof
from .detectors.dns_poison import detect_dns_poison
from .detectors.port_scan import detect_port_scans
from .detectors.dos_spike import detect_dos_spikes


def load_config():
    with open('config.yaml','r') as f:
        return yaml.safe_load(f)


def analyze_file(csv_path: str) -> Dict[str, List[dict]]:
    cfg = load_config()
    df = load_csv(csv_path)
    res = {}
    res['arp_spoof'] = detect_arp_spoof(
        df,
        window_seconds=cfg.get('window_seconds',60),
        max_mac_per_ip=cfg.get('arp_spoof',{}).get('max_mac_per_ip',1)
    )
    res['dns_poison'] = detect_dns_poison(
        df,
        window_seconds=cfg.get('window_seconds',60),
        ip_change_threshold=cfg.get('dns_poison',{}).get('ip_change_threshold',2),
        min_suspicious_ttl=cfg.get('dns_poison',{}).get('min_suspicious_ttl',60)
    )
    res['port_scans'] = detect_port_scans(
        df,
        window_seconds=cfg.get('window_seconds',60),
        unique_ports_threshold=cfg.get('port_scan',{}).get('unique_ports_threshold',30),
        max_destinations=cfg.get('port_scan',{}).get('max_destinations',4)
    )
    res['dos_spikes'] = detect_dos_spikes(
        df,
        window_seconds=1,
        pps_threshold=cfg.get('dos_spike',{}).get('pps_threshold',300)
    )
    return res
