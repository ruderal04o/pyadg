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
    # 如果URL列表为空，创建空文件并返回成功
    if not urls:
        print(f"No URLs provided for {output_file.name}, creating empty file.")
        open(output_file, 'w').close()
        return True
        
    success = False
    with open(output_file, 'w', encoding='utf-8') as out:
        for url in urls:
            try:
                print(f"Fetching: {url}")
                res = requests.get(url, timeout=15)
                res.raise_for_status()
                content = res.content
                if decode_base64:
                    try:
                        content = base64.b64decode(content)
                    except Exception as e:
                        print(f"Warning: Failed to decode base64 content from {url}: {e}")
                        print("Treating as plain text instead")
                lines = content.decode('utf-8', errors='ignore').splitlines()
                
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
    
    if success and os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        return True
    else:
        print(f"Warning: Failed to download any content for {output_file.name}, creating empty file")
        open(output_file, 'w').close()
        return True

def get_data(temp_dir):
    temp_dir.mkdir(exist_ok=True)
    all_success = True

    # DNS分流配置 - 可以在这里灵活添加/删除
    dns_config = {
        "domestic": ["udp://127.0.0.1:5335"],      # 国内DNS
        "foreign": ["udp://127.0.0.1:5337"],       # 国外DNS
        "white": "udp://127.0.0.1:5336",           # 白名单DNS
        "special": "udp://127.0.0.1:5338",         # 特殊列表DNS
        "block": "udp://127.0.0.1:5339",           # 拦截列表DNS
        "local": "[/home.arpa/] 192.168.136.1"     # 本地DNS
    }

    # 数据源配置 - 可以在这里灵活添加/删除
    data_sources = {
        "cnacc_domain": {
            "urls": [
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
                "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
                "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China_Domain.list"
            ],
            "decode_base64": False,
            "remove_leading_dot": True,
            "required": True
        },
        "cnacc_trusted": {
            "urls": [
                # 这里可以添加可信域名源
            ],
            "decode_base64": False,
            "remove_leading_dot": False,
            "required": False
        },
        "gfwlist_base64": {
            "urls": [
                "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt",
                "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
                "https://raw.githubusercontent.com/poctopus/gfwlist-plus/master/gfwlist-plus.txt"
            ],
            "decode_base64": True,
            "remove_leading_dot": False,
            "required": True
        },
        "gfwlist_domain": {
            "urls": [
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/greatfire.txt",
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
                "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Global/Global_Domain.list",
                "https://raw.githubusercontent.com/pexcn/gfwlist-extras/master/gfwlist-extras.txt"
            ],
            "decode_base64": False,
            "remove_leading_dot": True,
            "required": True
        },
        "modify_rules": {
            "urls": [
                "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/data_modify.jsonc"
            ],
            "decode_base64": False,
            "remove_leading_dot": False,
            "required": False
        },
        "white_list": {
            "urls": [
                "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/whitelist.txt",
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/apple-cn.txt",
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/google-cn.txt",
                "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf",
                "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf",
                "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/microsoft.txt"
            ],
            "decode_base64": False,
            "remove_leading_dot": False,
            "required": False
        },
        "block_list": {
            "urls": [
                # 这里可以添加拦截列表源
            ],
            "decode_base64": False,
            "remove_leading_dot": False,
            "required": False
        },
        "special_list": {
            "urls": [
                # 这里添加特殊分流列表的URL
                # 示例: "https://raw.githubusercontent.com/example/special-list/master/special.txt"
                "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/special_list.txt"
            ],
            "decode_base64": False,
            "remove_leading_dot": False,
            "required": False
        }
    }

    # 下载所有数据源
    for name, config in data_sources.items():
        output_file = temp_dir / f"{name}.tmp"
        success = download_to_file(
            urls=config["urls"],
            output_file=output_file,
            decode_base64=config["decode_base64"],
            remove_leading_dot=config["remove_leading_dot"]
        )
        
        if config["required"] and not success:
            all_success = False
            print(f"Error: Failed to download required file {name}")
    
    # 保存DNS配置到临时文件，供后续使用
    dns_config_file = temp_dir / "dns_config.json"
    with open(dns_config_file, 'w', encoding='utf-8') as f:
        json.dump(dns_config, f, indent=2)

    if not all_success:
        print("Error: Failed to download one or more required files. Exiting.")
        sys.exit(1)
        
    print("Data download complete.")
    return dns_config

def extract_domains(file_path, regex):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print(f"Warning: File {file_path} does not exist or is empty.")
        return []
        
    with open(file_path, encoding='utf-8') as f:
        lines = f.readlines()
    
    domains = set()
    for line in lines:
        line = line.strip().lower()
        
        # 跳过注释行和空行
        if not line or line.startswith('!') or line.startswith('#'):
            continue
            
        # 处理 AdGuard Home 格式的规则 (||domain.com^)
        if line.startswith('||') and line.endswith('^'):
            domain = line[2:-1]
            if domain.startswith('*.'):
                domain = domain[2:]
            if re.match(regex, domain):
                domains.add(domain)
            continue
            
        # 处理其他 AdGuard Home 格式
        elif line.startswith('||') and '^' in line:
            domain = line[2:line.index('^')]
            if domain.startswith('*.'):
                domain = domain[2:]
            if re.match(regex, domain):
                domains.add(domain)
            continue
            
        # 处理标准域名格式
        if line.startswith("full:"):
            line = line[5:]
            
        # 使用正则匹配标准域名
        if re.match(regex, line):
            domains.add(line)
    
    return sorted(domains)

def load_modify_rules(temp_dir):
    modify_file = temp_dir / "modify_rules.tmp"
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

def load_dns_config(temp_dir):
    dns_config_file = temp_dir / "dns_config.json"
    if not dns_config_file.exists():
        print("Warning: DNS config file does not exist, using defaults.")
        return {
            "domestic": ["udp://127.0.0.1:5335"],
            "foreign": ["udp://127.0.0.1:5337"],
            "white": "udp://127.0.0.1:5336",
            "special": "udp://127.0.0.1:5338",
            "block": "udp://127.0.0.1:5339",
            "local": "[/home.arpa/] 192.168.136.1"
        }
    
    with open(dns_config_file, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error loading DNS config: {e}")
            return {
                "domestic": ["udp://127.0.0.1:5335"],
                "foreign": ["udp://127.0.0.1:5337"],
                "white": "udp://127.0.0.1:5336",
                "special": "udp://127.0.0.1:5338",
                "block": "udp://127.0.0.1:5339",
                "local": "[/home.arpa/] 192.168.136.1"
            }

def build_domain_tree(domains):
    tree = {}
    for domain in domains:
        parts = domain.split('.')
        node = tree
        for part in reversed(parts):
            if part not in node:
                node[part] = {}
            node = node[part]
        node['__domain__'] = domain
    return tree

def find_domain_in_tree(domain, tree):
    matches = []
    parts = domain.split('.')
    
    node = tree
    for part in reversed(parts):
        if part not in node:
            break
        node = node[part]
        if '__domain__' in node:
            matches.append(node['__domain__'])
    else:
        if '__domain__' in node:
            matches.append(node['__domain__'])
    
    node = tree
    for i, part in enumerate(reversed(parts)):
        if '*' in node:
            if '__domain__' in node['*']:
                matches.append(node['*']['__domain__'])
        if part not in node:
            break
        node = node[part]
    
    return matches

def check_list_conflicts(all_domains):
    """
    检查所有列表之间的冲突
    """
    print("Checking for list conflicts...")
    
    # 构建域名树
    domain_trees = {}
    for list_name, domains in all_domains.items():
        domain_trees[list_name] = build_domain_tree(domains)
    
    # 优先级定义（从高到低）
    priority_order = ['white_list', 'block_list', 'special_list', 'cnacc', 'gfwlist']
    
    # 初始化解决后的域名集合
    resolved_domains = {name: set(domains) for name, domains in all_domains.items()}
    
    # 按照优先级解决冲突
    for i, high_priority in enumerate(priority_order):
        for j, low_priority in enumerate(priority_order[i+1:], i+1):
            if high_priority not in all_domains or low_priority not in all_domains:
                continue
                
            print(f"Resolving conflicts: {high_priority} vs {low_priority}")
            high_domains = resolved_domains[high_priority]
            low_domains = resolved_domains[low_priority]
            high_tree = domain_trees[high_priority]
            
            conflicts = set()
            for domain in list(low_domains):
                matches = find_domain_in_tree(domain, high_tree)
                if matches:
                    conflicts.add(domain)
            
            if conflicts:
                print(f"  Removing {len(conflicts)} domains from {low_priority} (conflict with {high_priority})")
                low_domains.difference_update(conflicts)
    
    # 转换为排序列表
    return {name: sorted(domains) for name, domains in resolved_domains.items()}

def apply_modify_rules(domains_dict, modify_rules):
    cnacc_set = set(domains_dict.get('cnacc', []))
    gfwlist_set = set(domains_dict.get('gfwlist', []))

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
    
    # 更新域名字典
    domains_dict['cnacc'] = sorted(cnacc_set)
    domains_dict['gfwlist'] = sorted(gfwlist_set)
    
    return domains_dict

def analyse_data(temp_dir):
    print("Analyzing data...")
    domain_regex = re.compile(r"^(([a-z]{1,2}|[a-z0-9][-\.a-z0-9]{1,61}[a-z0-9])\.)+([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$")

    # 提取所有域名列表
    domains_dict = {
        'cnacc_base': extract_domains(temp_dir / "cnacc_domain.tmp", domain_regex),
        'gfwlist_base': extract_domains(temp_dir / "gfwlist_base64.tmp", domain_regex),
        'gfwlist_domain': extract_domains(temp_dir / "gfwlist_domain.tmp", domain_regex),
        'white_list': extract_domains(temp_dir / "white_list.tmp", domain_regex),
        'cnacc_trusted': extract_domains(temp_dir / "cnacc_trusted.tmp", domain_regex),
        'block_list': extract_domains(temp_dir / "block_list.tmp", domain_regex),
        'special_list': extract_domains(temp_dir / "special_list.tmp", domain_regex)
    }
    
    # 合并GFW列表
    gfwlist_all = domains_dict['gfwlist_base'] + domains_dict['gfwlist_domain']
    domains_dict['gfwlist'] = sorted(set(gfwlist_all))
    
    # 移除重复的域名
    cnacc_raw = sorted(set(domains_dict['cnacc_base']) - set(domains_dict['gfwlist']))
    gfwlist_raw = sorted(set(domains_dict['gfwlist']) - set(domains_dict['cnacc_base']))
    
    # 处理可信域名
    gfwlist_filtered = sorted(set(gfwlist_raw) - set(domains_dict['cnacc_trusted']))
    cnacc_final = sorted(set(cnacc_raw).union(set(domains_dict['cnacc_trusted'])))
    
    # 更新域名字典
    domains_dict['cnacc'] = cnacc_final
    domains_dict['gfwlist'] = gfwlist_filtered
    
    # 检查必需列表是否为空
    if not domains_dict['cnacc']:
        print("Error: No CNACC domains extracted.")
        sys.exit(1)
    if not domains_dict['gfwlist']:
        print("Error: No GFWList domains extracted.")
        sys.exit(1)
    
    # 应用修改规则
    modify_rules = load_modify_rules(temp_dir)
    domains_dict = apply_modify_rules(domains_dict, modify_rules)
    
    # 检查并解决冲突
    # 只包含需要检查的列表
    check_lists = {k: v for k, v in domains_dict.items() 
                   if k in ['cnacc', 'gfwlist', 'white_list', 'block_list', 'special_list'] and v}
    resolved_domains = check_list_conflicts(check_lists)
    
    # 更新域名字典
    for name in resolved_domains:
        domains_dict[name] = resolved_domains[name]
    
    # 打印统计信息
    print("\n=== Domain Statistics ===")
    for list_name, domains in domains_dict.items():
        if domains and list_name not in ['cnacc_base', 'gfwlist_base', 'gfwlist_domain']:
            print(f"{list_name}: {len(domains)} domains")
    
    return domains_dict

def generate_adguardhome_rules(domains_dict, dns_config, output_dir):
    print("Generating AdGuardHome rules...")
    output_dir.mkdir(exist_ok=True)
    
    # 生成 whitelist.txt (国内优先策略)
    with open(output_dir / "whitelist.txt", 'w', encoding='utf-8') as f:
        # 基础DNS设置
        for dns in dns_config["foreign"]:
            f.write(f"{dns}\n")
        f.write(f"{dns_config['local']}\n")
        
        # 白名单规则
        if domains_dict.get('white_list'):
            f.write(f"[/{'/'.join(domains_dict['white_list'])}/] {dns_config['white']}\n")
        
        # 特殊列表规则
        if domains_dict.get('special_list'):
            f.write(f"[/{'/'.join(domains_dict['special_list'])}/] {dns_config['special']}\n")
        
        # CNACC规则
        if domains_dict.get('cnacc'):
            f.write(f"[/{'/'.join(domains_dict['cnacc'])}/] {' '.join(dns_config['domestic'])}\n")
        
        # 拦截列表规则
        if domains_dict.get('block_list'):
            f.write(f"[/{'/'.join(domains_dict['block_list'])}/] {dns_config['block']}\n")

    # 生成 blacklist.txt (国外优先策略)
    with open(output_dir / "blacklist.txt", 'w', encoding='utf-8') as f:
        # 基础DNS设置
        for dns in dns_config["domestic"]:
            f.write(f"{dns}\n")
        f.write(f"{dns_config['local']}\n")
        
        # 白名单规则
        if domains_dict.get('white_list'):
            f.write(f"[/{'/'.join(domains_dict['white_list'])}/] {dns_config['white']}\n")
        
        # 特殊列表规则
        if domains_dict.get('special_list'):
            f.write(f"[/{'/'.join(domains_dict['special_list'])}/] {dns_config['special']}\n")
        
        # 拦截列表规则
        if domains_dict.get('block_list'):
            f.write(f"[/{'/'.join(domains_dict['block_list'])}/] {dns_config['block']}\n")
        
        # GFWList规则
        if domains_dict.get('gfwlist'):
            f.write(f"[/{'/'.join(domains_dict['gfwlist'])}/] {' '.join(dns_config['foreign'])}\n")
    
    # 生成 special_list.txt (特殊列表单独文件，可选)
    if domains_dict.get('special_list'):
        with open(output_dir / "special_list.txt", 'w', encoding='utf-8') as f:
            for dns in dns_config["domestic"]:
                f.write(f"{dns}\n")
            f.write(f"{dns_config['local']}\n")
            f.write(f"[/{'/'.join(domains_dict['special_list'])}/] {dns_config['special']}\n")
    
    print(f"Rules generated in: {output_dir}")
    
    # 保存DNS配置供参考
    config_file = output_dir / "dns_config.json"
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(dns_config, f, indent=2)
    print(f"DNS configuration saved to: {config_file}")

    # 重启AdGuardHome服务
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

def create_example_configs():
    """创建示例配置文件"""
    script_dir = Path(__file__).parent.absolute()
    
    # 示例DNS配置
    example_dns_config = {
        "domestic": ["udp://127.0.0.1:5335"],
        "foreign": ["udp://127.0.0.1:5337"],
        "white": "udp://127.0.0.1:5336",
        "special": "udp://127.0.0.1:5338",
        "block": "udp://127.0.0.1:5339",
        "local": "[/home.arpa/] 192.168.136.1"
    }
    
    # 示例特殊列表源
    example_special_list = {
        "special_list": {
            "urls": [
                # 在这里添加特殊分流列表的URL
                # 例如:
                # "https://raw.githubusercontent.com/ruderal04o/pyadg/refs/heads/main/special_list",
                # "https://raw.githubusercontent.com/another/special-list/main/domains.txt"
            ],
            "decode_base64": False,
            "remove_leading_dot": False,
            "required": False
        }
    }
    
    # 保存示例配置
    config_dir = script_dir / "config_examples"
    config_dir.mkdir(exist_ok=True)
    
    with open(config_dir / "dns_config_example.json", 'w', encoding='utf-8') as f:
        json.dump(example_dns_config, f, indent=2)
    
    with open(config_dir / "special_sources_example.json", 'w', encoding='utf-8') as f:
        json.dump(example_special_list, f, indent=2)
    
    print(f"Example configurations created in: {config_dir}")

if __name__ == "__main__":
    script_dir = Path(__file__).parent.absolute()
    temp_path = script_dir / "Temp"
    output_path = script_dir / "gfwlist2adguard"
    
    # 创建示例配置（首次运行）
    if not (script_dir / "config_examples").exists():
        create_example_configs()
    
    try:
        dns_config = get_data(temp_path)
        domains_dict = analyse_data(temp_path)
        generate_adguardhome_rules(domains_dict, dns_config, output_path)
        print("\n=== 使用说明 ===")
        print("1. 要添加特殊分流列表，请在get_data()函数的data_sources['special_list']['urls']中添加URL")
        print("2. 要修改DNS服务器配置，请修改get_data()函数中的dns_config字典")
        print("3. 查看config_examples目录中的示例配置文件")
    except Exception as e:
        print(f"Script execution failed: {e}")
        sys.exit(1)