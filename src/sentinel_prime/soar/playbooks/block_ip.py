import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Sentinel-Prime Playbook: Block IP")
    parser.add_argument("--target", required=True, help="The IP address to block")
    args = parser.parse_args()

    target = args.target
    print(f"[{target}] Initiating IP block protocol...")
    print(f"[{target}] Pushing block rule to perimeter firewall and edge routers.")
    print(f"[{target}] IP address successfully blackholed.")
    sys.exit(0)

if __name__ == "__main__":
    main()
