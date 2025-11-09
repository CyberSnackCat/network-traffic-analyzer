
from scapy.all import sniff, ARP, DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP
import csv
from datetime import datetime
from pathlib import Path

FIELDS = [
    "ts","src","dst","proto","sport","dport","length",
    "arp_op","arp_psrc","arp_pdst","arp_hwsrc","arp_hwdst",
    "dns_qname","dns_an","dns_ttl"
]

def _row_defaults():
    return {k: "" for k in FIELDS}


def _packet_to_row(pkt):
    r = _row_defaults()
    r["ts"] = datetime.utcnow().isoformat()
    try:
        if IP in pkt:
            r["src"] = pkt[IP].src
            r["dst"] = pkt[IP].dst
            r["length"] = len(pkt)
            if TCP in pkt:
                r["proto"] = "TCP"
                r["sport"] = getattr(pkt[TCP], 'sport', '')
                r["dport"] = getattr(pkt[TCP], 'dport', '')
            elif UDP in pkt:
                r["proto"] = "UDP"
                r["sport"] = getattr(pkt[UDP], 'sport', '')
                r["dport"] = getattr(pkt[UDP], 'dport', '')
            else:
                r["proto"] = "IP"
        elif IPv6 in pkt:
            r["src"] = pkt[IPv6].src
            r["dst"] = pkt[IPv6].dst
            r["length"] = len(pkt)
            r["proto"] = "IPv6"
        if ARP in pkt:
            r["proto"] = "ARP"
            r["arp_op"] = pkt[ARP].op
            r["arp_psrc"] = pkt[ARP].psrc
            r["arp_pdst"] = pkt[ARP].pdst
            r["arp_hwsrc"] = pkt[ARP].hwsrc
            r["arp_hwdst"] = pkt[ARP].hwdst
        if DNS in pkt:
            # Query
            if pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR):
                try:
                    r["dns_qname"] = pkt[DNS].qd.qname.decode(errors='ignore').rstrip('.')
                except Exception:
                    r["dns_qname"] = str(pkt[DNS].qd.qname)
            # Answers
            answers = []
            ttl = None
            if pkt[DNS].an:
                an = pkt[DNS].an
                count = pkt[DNS].ancount
                for i in range(count):
                    rr = an[i]
                    if isinstance(rr, DNSRR):
                        answers.append(getattr(rr, 'rdata', ''))
                        ttl = getattr(rr, 'ttl', ttl)
            r["dns_an"] = ",".join([str(a) for a in answers])
            r["dns_ttl"] = ttl if ttl is not None else ""
    except Exception:
        pass
    return r


def live_capture(iface: str, out_csv: str):
    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if f.tell() == 0:
            writer.writeheader()
        def handle(pkt):
            row = _packet_to_row(pkt)
            writer.writerow(row)
        sniff(iface=iface, prn=handle, store=False)
