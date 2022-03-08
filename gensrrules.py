from typing import Iterable, Set
import requests
import base64

GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
TELEGRAM_CIDR_URL = "https://core.telegram.org/resources/cidr.txt"


def main():
    res = requests.get(GFWLIST_URL).text
    gfwlist = base64.b64decode(res).decode("utf-8").splitlines()
    ip_ranges = get_blocked_ip_ranges()
    with open("custom.txt") as f:
        customlist = f.readlines()
    combined = customlist.copy()
    for line in gfwlist:
        if line.startswith("[") or line.startswith("!"):
            continue
        combined.append(line)
    with open("fullrules.txt", "w") as f:
        f.write(f"[AutoProxy 0.2.9]\n")
        for line in combined:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")
    with open("fullrules.conf", "w") as f:
        f.write(convert_to_shadowrocket_rules(combined, ip_ranges))


def get_blocked_ip_ranges() -> Set[str]:
    telegram_ranges = requests.get(TELEGRAM_CIDR_URL).text.splitlines()
    result = {
        # Hardcoded values copied from https://github.com/h2y/Shadowrocket-ADBlock-Rules
        "67.198.55.0/24",
        "91.108.4.0/22",
        "91.108.8.0/22",
        "91.108.12.0/22",
        "91.108.16.0/22",
        "91.108.56.0/22",
        "109.239.140.0/24",
        "149.154.160.0/20",
        "149.154.164.0/22",
        "149.154.168.0/22",
        "149.154.172.0/22",
        "74.125.23.127/32",
        "14.102.250.18/32",
        "14.102.250.19/32",
        "174.142.105.153/32",
        "67.220.91.15/32",
        "67.220.91.18/32",
        "67.220.91.23/32",
        "69.65.19.160/32",
        "72.52.81.22/32",
        "85.17.73.31/32",
        "50.7.31.230/32",
    }
    for line in telegram_ranges:
        line = line.strip()
        if line:
            result.add(line)
    return result


def convert_to_shadowrocket_rules(
    lines: Iterable[str], ip_ranges: Iterable[str]
) -> str:
    # In Python 3.7+, dicts preserve insertion order but sets do not.
    # We need the insertion order so we emulate sets by dicts.
    domain_suffices = {}
    for line in lines:
        line = line.strip()
        if line.startswith("!"):
            continue
        if line.startswith("."):
            c = line[1:]
        elif line.startswith("|http://"):
            c = line[8:]
        elif line.startswith("||"):
            c = line[2:]
        else:
            continue
        domain_suffices[c.split("/")[0]] = True
    pieces = [
        """[General]
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, e.crashlytics.com, captive.apple.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system
[Rule]
DOMAIN-SUFFIX,cn,Direct
DOMAIN-SUFFIX,corp.google.com,Direct
DOMAIN-KEYWORD,google,Proxy
"""
    ]
    for d in domain_suffices.keys():
        pieces.append(f"DOMAIN-SUFFIX,{d},Proxy")
    for r in ip_ranges:
        pieces.append(f"IP-CIDR,{r},Proxy")
    pieces.append(
        """
FINAL,direct

[URL Rewrite]
^https?://(www.)?g(oogle)?.cn https://www.google.com 302
"""
    )
    return "\n".join(pieces)


if __name__ == "__main__":
    main()
