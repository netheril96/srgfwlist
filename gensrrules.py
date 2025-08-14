from typing import Dict, Iterable, List, Sequence, TextIO
import requests
import base64
import argparse
import json

GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
TELEGRAM_CIDR_URL = "https://core.telegram.org/resources/cidr.txt"


class TrieNode:
    value: str
    is_terminal: bool
    children: Dict[str, "TrieNode"]

    def __init__(self, value: str) -> None:
        self.value = value
        self.is_terminal = False
        self.children = {}


class Trie:
    def __init__(self) -> None:
        self._root = TrieNode("")

    def add_path(self, values: Iterable[str]) -> None:
        node = self._root
        for v in values:
            existing_node = node.children.get(v)
            if existing_node:
                if existing_node.is_terminal:
                    return
                node = existing_node
            else:
                new_node = TrieNode(v)
                node.children[v] = new_node
                node = new_node
        if node is not self._root:
            node.is_terminal = True

    def _traverse_all_paths(
        self, node: TrieNode, prefix: List[str]
    ) -> Iterable[List[str]]:
        current_list = prefix + [node.value]
        if node.is_terminal:
            yield current_list
        else:
            for c in node.children.values():
                yield from self._traverse_all_paths(c, current_list)

    def traverse_all_paths(self) -> Iterable[List[str]]:
        for c in self._root.children.values():
            yield from self._traverse_all_paths(c, [])


def gfwlist_to_domain_suffices(gfwlist: Iterable[str]) -> List[str]:
    domain_suffices = []
    for line in gfwlist:
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
        c = c.rstrip("/")
        if "/" in c:
            continue  # We only keep full domains, not anything with path in it.
        domain_suffices.append(c)
    return domain_suffices


def domainlist_to_domain_suffices(l: Iterable[str]) -> List[str]:
    domain_suffices = []
    for line in l:
        line = line.strip()
        if line:
            domain_suffices.append(line)
    return domain_suffices


def switchylist_to_domain_suffices(l: Iterable[str]) -> List[str]:
    domain_suffices = []
    for line in l:
        line = line.strip()
        if not line or line.endswith(" +direct"):
            continue
        if line.endswith(" +proxy"):
            line = line[: -len(" +proxy")]
        if line.startswith("*."):
            line = line[2:]
        domain_suffices.append(line)
    return domain_suffices


def combine_domain_suffices(*domain_suffices: Sequence[str]) -> List[str]:
    original_order: Dict[str, int] = {}
    counter = 0
    trie = Trie()
    for d in domain_suffices:
        for key in d:
            if "google" not in key:
                trie.add_path(key.split(".")[::-1])
                original_order.setdefault(key, counter)
                counter += 1
    result = [".".join(p[::-1]) for p in trie.traverse_all_paths()]
    result.sort(key=lambda p: original_order[p])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", help="Address of the server")
    parser.add_argument("--port", help="Port of the server", type=int, default=-1)
    parser.add_argument("--password", help="Password")
    args = parser.parse_args()
    gfwlist = (
        base64.b64decode(requests.get(GFWLIST_URL).text).decode("utf-8").splitlines()
    )
    d1 = gfwlist_to_domain_suffices(gfwlist=gfwlist)
    ip_ranges = get_blocked_ip_ranges()
    with open("custom.txt") as f:
        d2 = domainlist_to_domain_suffices(f)
    with open("switchy.txt") as f:
        d3 = switchylist_to_domain_suffices(f)
    combined = combine_domain_suffices(d3, d2, d1)
    with open("fullrules.conf", "w", newline="\n") as f:
        write_shadowrocket_rules(f, combined, ip_ranges)
    with open("domains.srs", mode="w", newline="\n") as f:
        write_sing_box_rules_for_domains(f, domain_suffices=combined)
    with open("ips.srs", mode="w", newline="\n") as f:
        write_sing_box_rules_for_ips(f, ip_ranges=ip_ranges)
    with open("fullrules.txt", "w", newline="\n") as f:
        f.write(
            """[Autoproxy]
/google/
@@||cn
@@||rsy.duckdns.org
@@||rsyhome.duckdns.org

"""
        )
        for key in combined:
            f.write(f"||{key}\n")
    if args.server:
        with open("leaf.conf", "w", newline="\n") as f:
            write_leaf_rules(
                f, combined, ip_ranges, args.server, args.port, args.password
            )


def get_blocked_ip_ranges() -> List[str]:
    telegram_ranges = requests.get(TELEGRAM_CIDR_URL).text.splitlines()
    result = set()
    for line in telegram_ranges:
        line = line.strip()
        if line:
            result.add(line)
    return sorted(result)


def write_shadowrocket_rules(
    f: TextIO, domain_suffices: Iterable[str], ip_ranges: Iterable[str]
) -> None:
    f.write(
        """[General]
ipv6 = true
prefer-ipv6 = true
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, localhost, *.local, e.crashlytics.com, captive.apple.com, *.rsy.duckdns.org, *.rsyhome.duckdns.org, *.cn, rsy.duckdns.org, rsyhome.duckdns.org
bypass-tun = fe80::/10, 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system
icmp-auto-reply=true
private-ip-answer=true
dns-direct-fallback-proxy=true
udp-policy-not-supported-behavior=DIRECT

[Rule]
DOMAIN-KEYWORD,google,Proxy
DOMAIN-SUFFIX,cn,Direct
DOMAIN-SUFFIX,rsyhome.duckdns.org,Direct
DOMAIN-SUFFIX,rsy.duckdns.org,Direct
"""
    )
    for d in domain_suffices:
        f.write(f"DOMAIN-SUFFIX,{d},Proxy\n")
    for r in ip_ranges:
        f.write(f"IP-CIDR,{r},Proxy\n")
    f.write(
        """
FINAL,direct

[URL Rewrite]
^https?://(www.)?g(oogle)?.cn https://www.google.com 302
"""
    )


def write_sing_box_rules_for_domains(f: TextIO, domain_suffices: Iterable[str]) -> None:
    rules = {
        "version": 2,
        "rules": [{"domain_keyword": "google"}, {"domain_suffix": domain_suffices}],
    }
    json.dump(rules, f, ensure_ascii=False)


def write_sing_box_rules_for_ips(f: TextIO, ip_ranges: Iterable[str]) -> None:
    rules = {
        "version": 2,
        "rules": [
            {"ip_cidr": ip_ranges},
        ],
    }
    json.dump(rules, f, ensure_ascii=False)


def write_leaf_rules(
    f: TextIO,
    domain_suffices: Iterable[str],
    ip_ranges: Iterable[str],
    server: str,
    port: int,
    password: str,
) -> None:
    f.write(
        f"""
[General]
always-real-ip = apple.com

[Proxy]
Direct = direct
Reject = reject
T = trojan, {server}, {port}, password={password}

[Rule]
EXTERNAL,site:category-ads-all,Reject
DOMAIN-SUFFIX,cn,Direct
DOMAIN-KEYWORD,google,T
DOMAIN-SUFFIX,rsyhome.duckdns.org,Direct
DOMAIN-SUFFIX,rsy.duckdns.org,Direct


"""
    )
    for d in domain_suffices:
        f.write(f"DOMAIN-SUFFIX,{d},T\n")
    for r in ip_ranges:
        f.write(f"IP-CIDR,{r},T\n")
    f.write(
        """
FINAL,Direct
    """
    )


if __name__ == "__main__":
    main()
