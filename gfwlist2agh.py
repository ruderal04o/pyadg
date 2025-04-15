#!/usr/bin/env python3
# gfwlist2agh.py

import os
import re
import base64
import requests
import shutil
import tempfile
from pathlib import Path
from collections import defaultdict

def download_to_file(urls, output_file, decode_base64=False, remove_leading_dot=False):
    with open(output_file, 'w', encoding='utf-8') as out:
        for url in urls:
            try:
                print(f"Fetching: {url}")
                res = requests.get(url, timeout=15)
                res.raise_for_status()
                content = res.content
                if decode_base64:
                    content = base64.b64decode(content)
                lines = content.decode('utf-8', errors='ignore').splitlines()
                for line in lines:
                    if remove_leading_dot:
                        line = line.lstrip('.')
                    out.write(line + '\n')
            except Exception as e:
                print(f"Failed to fetch {url}: {e}")

def get_data(temp_dir):
    temp_dir.mkdir(exist_ok=True)

    cnacc_domain = [
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/apple-cn.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/google-cn.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China_Domain.list"
    ]
    cnacc_trusted = [
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf",
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf"
    ]
    gfwlist_base64 = [
        "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt",
        "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
        "https://raw.githubusercontent.com/poctopus/gfwlist-plus/master/gfwlist-plus.txt"
    ]
    gfwlist_domain = [
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/greatfire.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Global/Global_Domain.list",
        "https://raw.githubusercontent.com/pexcn/gfwlist-extras/master/gfwlist-extras.txt"
    ]
    gfwlist2agh_modify = [
        "https://raw.githubusercontent.com/ruderal04o/GFWList2AGH/source/data/data_modify.txt"
    ]

    download_to_file(cnacc_domain, temp_dir / "cnacc_domain.tmp", remove_leading_dot=True)
    download_to_file(cnacc_trusted, temp_dir / "cnacc_trusted.tmp")
    download_to_file(gfwlist_base64, temp_dir / "gfwlist_base64.tmp", decode_base64=True)
    download_to_file(gfwlist_domain, temp_dir / "gfwlist_domain.tmp", remove_leading_dot=True)
    download_to_file(gfwlist2agh_modify, temp_dir / "gfwlist2agh_modify.tmp")

    print("Data download complete.")

def extract_domains(file_path, regex):
    with open(file_path, encoding='utf-8') as f:
        lines = f.readlines()
    return sorted(set(
        line.strip().lower()
        for line in lines
        if re.match(regex, line.strip().lower())
    ))

def analyse_data(temp_dir):
    print("Analyzing data...")
    domain_regex = re.compile(r"^(([a-z]{1,2}|[a-z0-9][-\.a-z0-9]{1,61}[a-z0-9])\.)+([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$")

    cnacc_checklist = extract_domains(temp_dir / "cnacc_domain.tmp", domain_regex)
    gfwlist_checklist = extract_domains(temp_dir / "gfwlist_domain.tmp", domain_regex)
    gfwlist_base64_list = extract_domains(temp_dir / "gfwlist_base64.tmp", domain_regex)
    gfwlist_checklist.extend(gfwlist_base64_list)
    gfwlist_checklist = sorted(set(gfwlist_checklist))

    cnacc_trust = extract_domains(temp_dir / "cnacc_trusted.tmp", domain_regex)

    cnacc_raw = sorted(set(cnacc_checklist) - set(gfwlist_checklist))
    gfwlist_raw = sorted(set(gfwlist_checklist) - set(cnacc_checklist))

    gfwlist_data = sorted(set(gfwlist_raw) - set(cnacc_trust))
    cnacc_data = sorted(set(cnacc_raw).union(set(cnacc_trust)))

    print(f"CNACC domains: {len(cnacc_data)}")
    print(f"GFWList domains: {len(gfwlist_data)}")

    return cnacc_data, gfwlist_data

def generate_adguardhome_rules(cnacc_data, gfwlist_data, output_dir):
    print("Generating AdGuardHome rules...")
    output_dir.mkdir(exist_ok=True)

    domestic_dns = [
        "https://doh.pub:443/dns-query",
        "tls://dns.alidns.com:853"
    ]
    foreign_dns = [
        "https://dns.opendns.com:443/dns-query",
        "tls://dns.google:853"
    ]
    local_dns = "[/home.arpa/]192.168.136.1"

    # Combine cnacc_data domains into one line for whitelist
    with open(output_dir / "whitelist.txt", 'w', encoding='utf-8') as f:
        for dns in foreign_dns:
            f.write(f"{dns}\n")
        f.write(f"{local_dns}\n")  # 添加本地DNS规则作为第一行
        f.write(f"[/{'/'.join(cnacc_data)}/] {' '.join(domestic_dns)}\n")

    # Combine gfwlist_data domains into one line for blacklist
    with open(output_dir / "blacklist.txt", 'w', encoding='utf-8') as f:
        for dns in domestic_dns:
            f.write(f"{dns}\n")
        f.write(f"{local_dns}\n")  # 添加本地DNS规则作为第一行
        f.write(f"[/{'/'.join(gfwlist_data)}/] {' '.join(foreign_dns)}\n")

    print("Rules generated in:", output_dir)

if __name__ == "__main__":
    temp_path = Path("./Temp")
    output_path = Path("./gfwlist2adguard")
    get_data(temp_path)
    cnacc, gfwlist = analyse_data(temp_path)
    generate_adguardhome_rules(cnacc, gfwlist, output_path)
