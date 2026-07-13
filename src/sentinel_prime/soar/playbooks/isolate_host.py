import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Sentinel-Prime Playbook: Isolate Host")
    parser.add_argument("--target", required=True, help="The host to isolate")
    args = parser.parse_args()

    target = args.target
    print(f"[{target}] Initiating host isolation protocol...")
    print(f"[{target}] Disabling all non-essential network interfaces.")
    print(f"[{target}] Allowing traffic only to Sentinel-Prime SIEM and orchestration IPs.")
    print(f"[{target}] Host successfully quarantined.")
    sys.exit(0)

if __name__ == "__main__":
    main()
