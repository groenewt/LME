"""Run the owner-local gateway or validate configuration without opening a listener."""
import argparse
import json
import sys
from .gateway import load_config, make_server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('run', 'check-config'))
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        config, policy = load_config(args.config)
        if args.command == 'check-config':
            print(json.dumps({'valid': True, 'mode': config.mode, 'principals': len(policy.principals), 'policy_sha256': policy.sha256}))
            return 0
        with make_server(config, policy) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        return 0
    except (ValueError, TypeError, OSError):
        print('sink gateway configuration or startup failed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
