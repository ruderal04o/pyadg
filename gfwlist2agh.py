#!/usr/bin/env python3
# gfwlist2agh.py

import os
import re
import base64
import requests
import shutil
import tempfile
import json
import subprocess  # 新增导入
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
        "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/data_modify.jsonc"
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
    
    domains = set()
    for line in lines:
        line = line.strip().lower()
        # 移除 "full:" 前缀（如果存在）
        if line.startswith("full:"):
            line = line[5:]
        # 检查是否符合域名格式
        if re.match(regex, line):
            domains.add(line)
    
    return sorted(domains)

def load_modify_rules(temp_dir):
    modify_file = temp_dir / "gfwlist2agh_modify.tmp"
    if not modify_file.exists():
        return {"suffix": [], "Domain": []}
    
    with open(modify_file, 'r', encoding='utf-8') as f:
        try:
            content = f.read()
            # 移除可能存在的注释
            content = re.sub(r'//.*?\n', '\n', content)
            return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"Error parsing modify rules: {e}")
            return {"suffix": [], "Domain": []}

def apply_modify_rules(cnacc_data, gfwlist_data, modify_rules):
    # 转换为集合便于操作
    cnacc_set = set(cnacc_data)
    gfwlist_set = set(gfwlist_data)
    
    # 处理后缀规则
    for suffix_group in modify_rules.get("suffix", []):
        white_suffix = suffix_group.get("White-suf", [])
        black_suffix = suffix_group.get("Black-suf", [])
        
        # 先清理现有匹配后缀的域名
        for suffix in white_suffix + black_suffix:
            # 构建匹配模式：精确匹配或点后缀匹配
            pattern = re.compile(r'^(.*\.)?' + re.escape(suffix) + '$')
            
            # 从白名单中移除匹配该后缀的域名
            to_remove = {domain for domain in cnacc_set if pattern.match(domain)}
            cnacc_set -= to_remove
            
            # 从黑名单中移除匹配该后缀的域名
            to_remove = {domain for domain in gfwlist_set if pattern.match(domain)}
            gfwlist_set -= to_remove
        
        # 然后添加新的后缀规则
        for suffix in white_suffix:
            # 添加到白名单
            cnacc_set.add(suffix)
        
        for suffix in black_suffix:
            # 添加到黑名单
            gfwlist_set.add(suffix)
    
    # 处理完整域名规则
    for domain_group in modify_rules.get("Domain", []):
        white_domains = [d.lower() for d in domain_group.get("White-Dom", [])]
        black_domains = [d.lower() for d in domain_group.get("Black-Dom", [])]
        
        # 处理白名单域名
        for domain in white_domains:
            # 从黑名单中移除
            gfwlist_set.discard(domain)
            # 添加到白名单
            cnacc_set.add(domain)
        
        # 处理黑名单域名
        for domain in black_domains:
            # 从白名单中移除
            cnacc_set.discard(domain)
            # 添加到黑名单
            gfwlist_set.add(domain)
    
    # 转换回排序列表
    cnacc_data = sorted(cnacc_set)
    gfwlist_data = sorted(gfwlist_set)
    
    return cnacc_data, gfwlist_data

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

    # 加载并应用自定义修改规则
    modify_rules = load_modify_rules(temp_dir)
    cnacc_data, gfwlist_data = apply_modify_rules(cnacc_data, gfwlist_data, modify_rules)

    print(f"CNACC domains: {len(cnacc_data)}")
    print(f"GFWList domains: {len(gfwlist_data)}")

    return cnacc_data, gfwlist_data

def generate_adguardhome_rules(cnacc_data, gfwlist_data, output_dir):
    print("Generating AdGuardHome rules...")
    output_dir.mkdir(exist_ok=True)

    domestic_dns = [
        "127695.alidns.com",
        "159156.alidns.com"
    ]
    foreign_dns = [
        "8.8.8.8"
    ]
    local_dns = "[/home.arpa/]192.168.136.1"

    # Combine cnacc_data domains into one line for whitelist
    with open(output_dir / "whitelist.txt", 'w', encoding='utf-8') as f:
        for dns in foreign_dns:
            f.write(f"{dns}\n")
        f.write(f"{local_dns}\n")
        f.write(f"[/{'/'.join(cnacc_data)}/] {' '.join(domestic_dns)}\n")

    # Combine gfwlist_data domains into one line for blacklist
    with open(output_dir / "blacklist.txt", 'w', encoding='utf-8') as f:
        for dns in domestic_dns:
            f.write(f"{dns}\n")
        f.write(f"{local_dns}\n")
        f.write(f"[/{'/'.join(gfwlist_data)}/] {' '.join(foreign_dns)}\n")

    print("Rules generated in:", output_dir)
    
    # 新增：重启AdGuardHome服务
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
    temp_path = Path("./Temp")
    output_path = Path("./gfwlist2adguard")
    get_data(temp_path)
    cnacc, gfwlist = analyse_data(temp_path)
    generate_adguardhome_rules(cnacc, gfwlist, output_path)
    
