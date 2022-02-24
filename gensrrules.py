import requests
import base64
import datetime

GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
PORN_DOMAIN_URL = (
    "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/master/block.txt"
)


def main():
    res = requests.get(GFWLIST_URL).text
    gfwlist = base64.b64decode(res).decode("utf-8").split("\n")
    pornlist = requests.get(PORN_DOMAIN_URL).text.split("\n")
    with open("custom.txt") as f:
        customlist = f.readlines()
    combined = customlist.copy()
    for line in gfwlist:
        if line.startswith("[") or line.startswith("!"):
            continue
        combined.append(line)
    for line in pornlist:
        line = line.strip()
        if not line:
            continue
        combined.append("||" + line)
    with open("fullrules.txt", "w") as f:
        f.write(
            f"[AutoProxy 0.2.9]\n!Generated at {datetime.datetime.now(tz=datetime.timezone.utc).isoformat()}\n"
        )
        for line in combined:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")
    with open("fullrules.conf", "w") as f:
        f.write(convert_to_shadowrocket_rules(combined))


def convert_to_shadowrocket_rules(lines):
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
bypass-system = false
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, e.crashlytics.com, captive.apple.com
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system, 114.114.114.114
[Rule]
DOMAIN-SUFFIX,cn,Direct
DOMAIN-KEYWORD,blogspot,Proxy
DOMAIN-KEYWORD,google,Proxy
DOMAIN-KEYWORD,phobos,Proxy
IP-CIDR,67.198.55.0/24,Proxy
IP-CIDR,91.108.4.0/22,Proxy
IP-CIDR,91.108.8.0/22,Proxy
IP-CIDR,91.108.12.0/22,Proxy
IP-CIDR,91.108.16.0/22,Proxy
IP-CIDR,91.108.56.0/22,Proxy
IP-CIDR,109.239.140.0/24,Proxy
IP-CIDR,149.154.160.0/20,Proxy
IP-CIDR,149.154.164.0/22,Proxy
IP-CIDR,149.154.168.0/22,Proxy
IP-CIDR,149.154.172.0/22,Proxy
IP-CIDR,74.125.23.127/32,Proxy
IP-CIDR,14.102.250.18/32,Proxy
IP-CIDR,14.102.250.19/32,Proxy
IP-CIDR,174.142.105.153/32,Proxy
IP-CIDR,67.220.91.15/32,Proxy
IP-CIDR,67.220.91.18/32,Proxy
IP-CIDR,67.220.91.23/32,Proxy
IP-CIDR,69.65.19.160/32,Proxy
IP-CIDR,72.52.81.22/32,Proxy
IP-CIDR,85.17.73.31/32,Proxy
IP-CIDR,50.7.31.230/32,Proxy
"""
    ]
    for d in domain_suffices.keys():
        pieces.append(f"DOMAIN-SUFFIX,{d},Proxy")
    pieces.append(
        """
FINAL,direct

[URL Rewrite]
^http://(www.)?google.cn https://www.google.com 302
"""
    )
    return "\n".join(pieces)


if __name__ == "__main__":
    main()
