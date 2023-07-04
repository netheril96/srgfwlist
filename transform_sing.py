#!/usr/bin/env python3
import json
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=str, help="", required=True)
    parser.add_argument("--conf", type=str, help="", required=True)
    parser.add_argument("--out", type=str, help="", required=True)
    args = parser.parse_args()
    domain_suffixes = []
    ip_cidr = []
    with open(args.conf) as f:
        for line in f:
            line = line.lower().strip()
            if line.startswith("DOMAIN-SUFFIX,".lower()) and line.endswith(
                ",Proxy".lower()
            ):
                domain_suffixes.append(line.split(",")[1])
            if line.startswith("IP-CIDR,".lower()) and line.endswith(",Proxy".lower()):
                ip_cidr.append(line.split(",")[1])
    with open(args.template) as f:
        template = json.load(f)
    for rule in template["dns"]["rules"]:
        if rule.get("server") in {"my", "fakeip"} and "domain_suffix" in rule:
            rule["domain_suffix"] = domain_suffixes
    for rule in template["route"]["rules"]:
        if (
            rule.get("outbound") == "proxy"
            and "domain_suffix" in rule
            and "ip_cidr" in rule
        ):
            rule["domain_suffix"] = domain_suffixes
            rule["ip_cidr"] = ip_cidr
    with open(args.out, "w", newline='\n') as f:
        json.dump(template, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
