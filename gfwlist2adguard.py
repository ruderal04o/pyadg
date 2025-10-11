#!/usr/bin/env python3
# gfwlist2agh.py
import os
import re
import base64
import requests
import shutil
import tempfile
import json
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

def download_to_file(urls, output_file, decode_base64=False, remove_leading_dot=False):
    success = False
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
                
                # 检查内容是否为空
                if not lines or all(not line.strip() for line in lines):
                    print(f"Warning: Empty content from {url}")
                    continue
                    
                for line in lines:
                    if remove_leading_dot:
                        line = line.lstrip('.')
                    out.write(line + '\n')
                success = True
                print(f"Successfully downloaded from {url}")
            except Exception as e:
                print(f"Failed to fetch {url}: {e}")
    
    # 检查最终文件是否为空
    if success and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        return True
    else:
        print(f"Error: Failed to download any content for {output_file.name}")
        if os.path.exists(output_file):
            os.remove(output_file)
        return False

def get_data(temp_dir):
    temp_dir.mkdir(exist_ok=True)
    all_success = True

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
        "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/data_modify.jsonc"
    ]
    white_list = [
        "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/whitelist.txt"
    ]

    if not download_to_file(cnacc_domain, temp_dir / "cnacc_domain.tmp", remove_leading_dot=True):
        all_success = False
    if not download_to_file(cnacc_trusted, temp_dir / "cnacc_trusted.tmp"):
        all_success = False
    if not download_to_file(gfwlist_base64, temp_dir / "gfwlist_base64.tmp", decode_base64=True):
        all_success = False
    if not download_to_file(gfwlist_domain, temp_dir / "gfwlist_domain.tmp", remove_leading_dot=True):
        all_success = False
    if not download_to_file(gfwlist2agh_modify, temp_dir / "gfwlist2agh_modify.tmp"):
        all_success = False
    if not download_to_file(white_list, temp_dir / "white_list.tmp"):
        all_success = False

    if not all_success:
        print("Error: Failed to download one or more required files. Exiting.")
        sys.exit(1)
        
    print("Data download complete.")

def extract_domains(file_path, regex):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print(f"Error: File {file_path} does not exist or is empty.")
        return []
        
    with open(file_path, encoding='utf-8') as f:
        lines = f.readlines()
    
    domains = set()
    for line in lines:
        line = line.strip().lower()
        if line.startswith("full:"):
            line = line[5:]
        if re.match(regex, line):
            domains.add(line)
    
    return sorted(domains)

def load_modify_rules(temp_dir):
    modify_file = temp_dir / "gfwlist2agh_modify.tmp"
    if not modify_file.exists() or os.path.getsize(modify_file) == 0:
        print("Warning: Modify rules file does not exist or is empty.")
        return {"suffix": [], "Domain": []}
    
    with open(modify_file, 'r', encoding='utf-8') as f:
        try:
            content = f.read()
            content = re.sub(r'//.*?\n', '\n', content)
            return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"Error parsing modify rules: {e}")
            return {"suffix": [], "Domain": []}

def apply_modify_rules(cnacc_data, gfwlist_data, modify_rules):
    cnacc_set = set(cnacc_data)
    gfwlist_set = set(gfwlist_data)

    for suffix_group in modify_rules.get("suffix", []):
        white_suffix = suffix_group.get("White-suf", [])
        black_suffix = suffix_group.get("Black-suf", [])

        for suffix in white_suffix + black_suffix:
            pattern = re.compile(r'^(.*\.)?' + re.escape(suffix) + '$')

            to_remove = {domain for domain in cnacc_set if pattern.match(domain)}
            cnacc_set -= to_remove

            to_remove = {domain for domain in gfwlist_set if pattern.match(domain)}
            gfwlist_set -= to_remove

        for suffix in white_suffix:
            cnacc_set.add(suffix)
        
        for suffix in black_suffix:
            gfwlist_set.add(suffix)

    for domain_group in modify_rules.get("Domain", []):
        white_domains = [d.lower() for d in domain_group.get("White-Dom", [])]
        black_domains = [d.lower() for d in domain_group.get("Black-Dom", [])]

        for domain in white_domains:
            gfwlist_set.discard(domain)
            cnacc_set.add(domain)

        for domain in black_domains:
            cnacc_set.discard(domain)
            gfwlist_set.add(domain)

    cnacc_data = sorted(cnacc_set)
    gfwlist_data = sorted(gfwlist_set)
    
    return cnacc_data, gfwlist_data

def analyse_data(temp_dir):
    print("Analyzing data...")
    domain_regex = re.compile(r"^(([a-z]{1,2}|[a-z0-9][-\.a-z0-9]{1,61}[a-z0-9])\.)+([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$")

    cnacc_checklist = extract_domains(temp_dir / "cnacc_domain.tmp", domain_regex)
    gfwlist_checklist = extract_domains(temp_dir / "gfwlist_domain.tmp", domain_regex)
    gfwlist_base64_list = extract_domains(temp_dir / "gfwlist_base64.tmp", domain_regex)
    white_list_domains = extract_domains(temp_dir / "white_list.tmp", domain_regex)
    
    # 检查提取的数据是否为空
    if not cnacc_checklist:
        print("Error: No CNACC domains extracted.")
        sys.exit(1)
    if not gfwlist_checklist and not gfwlist_base64_list:
        print("Error: No GFWList domains extracted.")
        sys.exit(1)
        
    gfwlist_checklist.extend(gfwlist_base64_list)
    gfwlist_checklist = sorted(set(gfwlist_checklist))

    cnacc_trust = extract_domains(temp_dir / "cnacc_trusted.tmp", domain_regex)

    cnacc_raw = sorted(set(cnacc_checklist) - set(gfwlist_checklist))
    gfwlist_raw = sorted(set(gfwlist_checklist) - set(cnacc_checklist))

    gfwlist_data = sorted(set(gfwlist_raw) - set(cnacc_trust))
    cnacc_data = sorted(set(cnacc_raw).union(set(cnacc_trust)))

    modify_rules = load_modify_rules(temp_dir)
    cnacc_data, gfwlist_data = apply_modify_rules(cnacc_data, gfwlist_data, modify_rules)

    # 检查最终数据是否为空
    if not cnacc_data:
        print("Error: Final CNACC data is empty.")
        sys.exit(1)
    if not gfwlist_data:
        print("Error: Final GFWList data is empty.")
        sys.exit(1)

    print(f"CNACC domains: {len(cnacc_data)}")
    print(f"GFWList domains: {len(gfwlist_data)}")
    print(f"White list domains: {len(white_list_domains)}")

    return cnacc_data, gfwlist_data, white_list_domains

def generate_adguardhome_rules(cnacc_data, gfwlist_data, white_list_domains, output_dir):
    print("Generating AdGuardHome rules...")
    output_dir.mkdir(exist_ok=True)

    domestic_dns = [
        "quic://159156.alidns.com:853",
        "quic://127695.alidns.com:853"
    ]
    foreign_dns = [
        "tls://8.8.8.8"
    ]
    white_list_dns = "127.0.0.1:5353"
    local_dns = "[/home.arpa/]192.168.136.1"

    with open(output_dir / "whitelist.txt", 'w', encoding='utf-8') as f:
        for dns in foreign_dns:
            f.write(f"{dns}\n")
        f.write(f"{local_dns}\n")
        # 添加白名单域名规则，使用127.0.0.1:5353解析
        if white_list_domains:
            f.write(f"[/{'/'.join(white_list_domains)}/] {white_list_dns}\n")
        f.write(f"[/{'/'.join(cnacc_data)}/] {' '.join(domestic_dns)}\n")

    with open(output_dir / "blacklist.txt", 'w', encoding='utf-8') as f:
        for dns in domestic_dns:
            f.write(f"{dns}\n")
        f.write(f"{local_dns}\n")
        # 添加白名单域名规则，使用127.0.0.1:5353解析
        if white_list_domains:
            f.write(f"[/{'/'.join(white_list_domains)}/] {white_list_dns}\n")
        f.write(f"[/{'/'.join(gfwlist_data)}/] {' '.join(foreign_dns)}\n")

    print("Rules generated in:", output_dir)

    try:
        print("Restarting AdGuardHome service...")
        subprocess.run(["systemctl", "restart", "AdGuardHome.service"], check=True)
        print("AdGuardHome service restarted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to restart AdGuardHome service: {e}")
    except FileNotFoundError:
        print("systemctl command not found. Are you running this on a systemd system?")
    except PermissionError:
        print("Permission denied. Try running this script with sudo.")

if __name__ == "__main__":
    script_dir = Path(__file__).parent.absolute()
    temp_path = script_dir / "Temp"
    output_path = script_dir / "gfwlist2adguard"
    
    try:
        get_data(temp_path)
        cnacc, gfwlist, white_list = analyse_data(temp_path)
        generate_adguardhome_rules(cnacc, gfwlist, white_list, output_path)
    except Exception as e:
        print(f"Script execution failed: {e}")
        sys.exit(1)
