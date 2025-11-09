
import argparse
from pathlib import Path
from src.capture import live_capture
from src.analyze import analyze_file
from src.dashboard import build_report


def main():
    parser = argparse.ArgumentParser(description="Net Sec Traffic Analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_cap = sub.add_parser("capture", help="Capture live traffic to CSV")
    p_cap.add_argument("--iface", required=True, help="Network interface to sniff")
    p_cap.add_argument("--out", default="data/logs.csv", help="CSV output path")

    p_an = sub.add_parser("analyze", help="Run detectors on a CSV log")
    p_an.add_argument("--input", required=True, help="Input CSV path")
    p_an.add_argument("--report", action="store_true", help="Also build HTML report")

    args = parser.parse_args()

    if args.cmd == "capture":
        Path("data").mkdir(parents=True, exist_ok=True)
        live_capture(args.iface, args.out)
    elif args.cmd == "analyze":
        results = analyze_file(args.input)
        print("
=== DETECTION SUMMARY ===")
        for k, v in results.items():
            print(f"{k}: {len(v)} findings")
        if args.report:
            Path("reports").mkdir(parents=True, exist_ok=True)
            out = build_report(args.input, results)
            print(f"Report saved to: {out}")


if __name__ == "__main__":
    main()
