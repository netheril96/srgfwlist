from typing import Dict, Iterable, List, Sequence
import requests
import base64


GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
TELEGRAM_CIDR_URL = "https://core.telegram.org/resources/cidr.txt"
LOYAL_URL = "https://cn-blocked-domain.trli.club/domains.txt"


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
        domain_suffices.append(c.split("/")[0])
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
    gfwlist = (
        base64.b64decode(requests.get(GFWLIST_URL).text).decode("utf-8").splitlines()
    )
    d1 = gfwlist_to_domain_suffices(gfwlist=gfwlist)
    ip_ranges = get_blocked_ip_ranges()
    with open("custom.txt") as f:
        d2 = domainlist_to_domain_suffices(f)
    with open("switchy.txt") as f:
        d3 = switchylist_to_domain_suffices(f)
    d4 = domainlist_to_domain_suffices(requests.get(LOYAL_URL).text.splitlines())
    combined = combine_domain_suffices(d3, d2, d1, d4)
    with open("fullrules.conf", "w", newline="\n") as f:
        f.write(convert_to_shadowrocket_rules(combined, ip_ranges))
    with open("fullrules.txt", "w", newline="\n") as f:
        f.write(
            """[Autoproxy]
@@||corp.google.com
/google/
@@||rsy.duckdns.org
@@||rsyhome.duckdns.org

"""
        )
        for key in combined:
            f.write(f"||{key}\n")


def get_blocked_ip_ranges() -> List[str]:
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
    return sorted(result)


def convert_to_shadowrocket_rules(
    domain_suffices: Iterable[str], ip_ranges: Iterable[str]
) -> str:
    pieces = [
        """[General]
ipv6 = true
prefer-ipv6 = true
bypass-system = true
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, e.crashlytics.com, captive.apple.com, *.rsy.duckdns.org, *.rsyhome.duckdns.org
bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = system
[Rule]
DOMAIN-SUFFIX,corp.google.com,Direct
DOMAIN-KEYWORD,google,Proxy
DOMAIN-SUFFIX,rsyhome.duckdns.org,Direct
DOMAIN-SUFFIX,rsy.duckdns.org,Direct
"""
    ]
    for d in domain_suffices:
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
