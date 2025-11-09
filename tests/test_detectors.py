
import json
from src.analyze import analyze_file

def test_sample_detects():
    res = analyze_file('data/samples/synthetic_log.csv')
    # Expect at least one finding in each category from the synthetic data
    assert len(res['arp_spoof']) >= 1
    assert len(res['dns_poison']) >= 1
    assert len(res['port_scans']) >= 1
    assert len(res['dos_spikes']) >= 1
    print(json.dumps(res, indent=2))
