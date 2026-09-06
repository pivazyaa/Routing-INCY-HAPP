"""Provider helper: insert current routing into a private text subscription.

Use on the server that already serves the user's subscription. Never publish
the resulting file in the public routing repository. Supports text/base64
share-link subscriptions; full JSON configs require provider integration.
"""
import argparse
import base64
import json
from pathlib import Path

from update import routing_link

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "socks://", "hysteria2://", "hy2://", "tuic://")


def combine(body, profile):
    text = body.decode("utf-8-sig").strip()
    if not any(line.strip().lower().startswith(SCHEMES) for line in text.splitlines()):
        try:
            compact = "".join(text.split())
            text = base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True).decode("utf-8-sig")
        except (ValueError, UnicodeError):
            raise ValueError("Expected text or base64 share-link subscription; JSON needs provider integration") from None
    if not any(line.strip().lower().startswith(SCHEMES) for line in text.splitlines()):
        raise ValueError("Subscription has no supported server links")
    kept = []
    for line in text.splitlines():
        value = line.strip()
        lower = value.lower()
        if not value or "://routing/" in lower or "://autorouting/" in lower:
            continue
        if lower.startswith(("#profile-update-interval:", "#routing-enable:", "#routing:", "#autorouting:")):
            continue
        kept.append(line)
    return "#profile-update-interval: 12\n" + routing_link("Happ", profile) + "\n" + "\n".join(kept) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Private upstream subscription file")
    parser.add_argument("--routing", type=Path, default=Path(__file__).parent / "dist/Happ-YOTA-Whitelist.json")
    parser.add_argument("--output", required=True, type=Path, help="Private web-server subscription file, outside this repository")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parent
    output = args.output.resolve()
    if output.is_relative_to(repository) or output == args.input.resolve():
        parser.error("Output must be outside the public repository and must not overwrite input")
    if not output.parent.is_dir():
        parser.error("Private output directory must already exist")
    profile = json.loads(args.routing.read_text(encoding="utf-8"))
    result = combine(args.input.read_bytes(), profile)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(result, encoding="utf-8", newline="\n")
    temporary.replace(output)
    print("Private subscription prepared; no server credentials printed.")


if __name__ == "__main__":
    main()
