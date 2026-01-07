#!/usr/bin/python3
# coding=utf-8

import nmap
import datetime
import json
import os
import subprocess
import atexit
from multiprocessing import Pool

# ================== 终端保护 ==================
def _reset_terminal():
    try:
        subprocess.run(['stty', 'sane'], stderr=subprocess.DEVNULL)
    except:
        pass

atexit.register(_reset_terminal)
# =============================================

# ================== 配置 ==================
ip_file = 'ips.txt'
masscan_exe = './masscan'
muki_exe = './muki'
httpx_exe = './httpx'  # ✅ 使用本地 ./httpx
process_num = 50

# 创建 result 目录
result_dir = "result"
os.makedirs(result_dir, exist_ok=True)

# 生成带时间戳的文件路径
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
masscan_file = os.path.join(result_dir, f"masscan_{timestamp}.json")
httpx_ip_file = os.path.join(result_dir, f"httpx_ips_{timestamp}.txt")
httpx_output_file = os.path.join(result_dir, f"httpx_results_{timestamp}.txt")
muki_input_file = os.path.join(result_dir, f"muki_targets_{timestamp}.txt")
muki_output_file = os.path.join(result_dir, f"muki_results_{timestamp}.xlsx")
final_output_file = os.path.join(result_dir, f"services_{timestamp}.txt")
ping_output_file = os.path.join(result_dir, f"alive_ips_{timestamp}.txt")

# ========== 扫描端口配置 ==========
ALIVE_PORTS = [21, 22, 53, 80, 443, 445, 1433, 3306, 3389, 8080]
ALIVE_PORTS_STR = ','.join(map(str, ALIVE_PORTS))

RCE_PORTS = [
    21, 22, 23, 25, 80, 135, 139, 443, 445, 514, 515, 594, 600,
    1433, 1494, 1521, 2049, 2598, 27017, 3306, 3389, 4786, 4848,
    4990, 5432, 5555, 5556, 6066, 6379, 6443, 7000, 7001, 7002,
    7003, 7004, 7070, 7071, 8000, 8001, 8002, 8003, 8009, 8069,
    8080, 8081, 8083, 8088, 8090, 8093, 8383, 8500, 8686, 8880,
    8983, 9000, 9001, 9002, 9003, 9012, 9080, 9090, 9200, 9300,
    9503, 10990, 10999, 11099, 11111, 12721, 12900, 45000, 45001,
    47001, 47002, 50500, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007
]
RCE_PORTS = sorted(set(RCE_PORTS))
RCE_PORTS_STR = ','.join(map(str, RCE_PORTS))
# ==========================================

total_ports = 0
nmap_results = []


def select_ports():
    print("1) 全端口 (1-65535)")
    print("2) 常见 RCE / 高危端口")
    print("3) 存活检测（关键端口）")
    print("4) IP 存活检测（Ping Scan）")
    while True:
        choice = input("请选择扫描类型 (1/2/3/4): ").strip()
        if choice == '1':
            return '1-65535', False
        elif choice == '2':
            return RCE_PORTS_STR, False
        elif choice == '3':
            return ALIVE_PORTS_STR, False
        elif choice == '4':
            return None, True
        else:
            print("❌ 请输入 1、2、3 或 4。")


def select_rate():
    default_rate = 2000
    try:
        user_input = input(f"请输入 masscan 扫描速率（包/秒，默认 {default_rate}）: ").strip()
        if not user_input:
            return default_rate
        rate = int(user_input)
        return rate if rate > 0 else default_rate
    except ValueError:
        print("⚠️  输入无效，使用默认速率。")
        return default_rate


def select_muki_mode():
    while True:
        choice = input("是否对 Web 服务使用 muki 进行指纹识别？(y/n): ").strip().lower()
        if choice in ['n', 'no']:
            return None
        elif choice in ['y', 'yes']:
            while True:
                active = input("  是否启用主动探测（会发送额外请求）？(y/n): ").strip().lower()
                if active in ['y', 'yes']:
                    return True
                elif active in ['n', 'no']:
                    return False
                else:
                    print("  ❌ 请输入 y 或 n。")
        else:
            print("❌ 请输入 y 或 n。")


def run_masscan(port_range, rate):
    command = [
        'sudo', masscan_exe,
        '-iL', ip_file,
        '-p', port_range,
        '-oJ', masscan_file,
        '--rate', str(rate)
    ]
    print('\n🔄 正在执行 masscan 命令:\n', ' '.join(command))
    try:
        result = subprocess.run(command)
        if result.returncode != 0:
            print("[!] ❌ masscan 扫描失败。")
            exit(1)
        print("[+] ✅ masscan 扫描完成。")
    except KeyboardInterrupt:
        print("\n[!] 用户中断 masscan 扫描")
        exit(1)


def load_ip_ports():
    global total_ports
    if not os.path.exists(masscan_file):
        print(f"[!] ❌ {masscan_file} 未生成，请检查 masscan 是否成功运行。")
        return []

    try:
        with open(masscan_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] ❌ 解析 {masscan_file} 失败: {e}")
        return []

    ip_ports = []
    for item in data:
        ip = item.get('ip')
        for port_info in item.get('ports', []):
            port = port_info.get('port')
            if ip and port is not None:
                ip_ports.append(f"{ip}:{port}")
    
    total_ports = len(ip_ports)
    print(f"[+] ✅ 从 {masscan_file} 加载了 {total_ports} 个开放端口。")
    return ip_ports


def nmap_scan(ip_port):
    try:
        ip, port = ip_port.split(':', 1)
        nm = nmap.PortScanner()
        ret = nm.scan(ip, port, arguments='-Pn -sS')
        port_info = ret['scan'][ip]['tcp'][int(port)]
        service = port_info.get('name', 'unknown')
        result = f"{ip}:{port}:{service}"
        print(result)
        return result
    except Exception:
        result = f"{ip}:{port}:ERROR"
        print(result)
        return result


def run_nmap(ip_ports):
    global nmap_results
    if not ip_ports:
        print("[!] ⚠️  无开放端口，跳过 Nmap 扫描。")
        return

    print(f"\n[+] 🔍 开始 Nmap 服务识别（{process_num} 进程）...")
    with Pool(processes=process_num) as pool:
        results = []
        for result in pool.imap_unordered(nmap_scan, ip_ports, chunksize=1):
            results.append(result)
    nmap_results = results
    print(f"[+] ✅ Nmap 识别完成，共 {len(results)} 个结果。")


# ========= 核心：使用 ./httpx -l ip_list.txt =========
def run_httpx():
    """
    提取唯一 IP 列表，调用 ./httpx -l ips.txt -o results.txt
    """
    NON_WEB_SERVICES = {
        'ssh', 'telnet', 'rdp', 'vnc', 'ftp', 'ftps', 'tftp', 'sftp',
        'smtp', 'smtps', 'pop3', 'pop3s', 'imap', 'imaps', 'nntp',
        'mysql', 'oracle', 'mssql', 'postgresql', 'redis', 'mongodb', 'memcached',
        'ldap', 'ldaps', 'kerberos', 'radius', 'smb', 'netbios-ssn', 'microsoft-ds',
        'domain', 'ntp', 'snmp', 'syslog', 'bootps', 'irc', 'xmpp', 'sip', 'rtsp',
        'dhcp', 'ups', 'vmware', 'ipmi'
    }
    NON_WEB_PORTS = {
        7, 13, 17, 19, 22, 23, 53, 67, 68, 69, 110, 123, 137, 138, 139,
        143, 161, 162, 445, 514, 520, 1433, 1521, 3306, 3389, 5432,
        6379, 27017, 11211, 25, 465, 587, 993, 995,
        389, 636, 88, 500, 1025, 1434, 111, 135
    }

    # 提取有效 IP（只要有一个非排除端口就保留）
    valid_ips = set()
    for line in nmap_results:
        parts = line.strip().split(':', 2)
        if len(parts) != 3:
            continue
        ip, port_str, service = parts
        try:
            port = int(port_str)
        except:
            continue
        if port in NON_WEB_PORTS or service.lower() in NON_WEB_SERVICES:
            continue
        valid_ips.add(ip)

    if not valid_ips:
        print("[!] ⚠️  无潜在 Web 主机，跳过 httpx。")
        return []

    # 写入 IP 列表
    with open(httpx_ip_file, 'w') as f:
        for ip in sorted(valid_ips):
            f.write(ip + '\n')

    # 调用本地 ./httpx
    httpx_cmd = [httpx_exe, '-l', httpx_ip_file, '-o', httpx_output_file]
    print(f"\n[+] 🔎 正在运行 httpx 存活检测（{len(valid_ips)} 个IP）...")
    print(f"    命令: {' '.join(httpx_cmd)}")
    
    try:
        result = subprocess.run(httpx_cmd, capture_output=True, text=True)
        if result.returncode not in [0, 1]:
            print(f"[!] ❌ httpx 执行失败: {result.stderr}")
            return []
    except FileNotFoundError:
        print(f"[!] ❌ {httpx_exe} 未找到，请确保它在当前目录且有执行权限")
        return []
    except Exception as e:
        print(f"[!] ❌ httpx 异常: {e}")
        return []

    # 读取结果
    if not os.path.exists(httpx_output_file):
        print("[!] ⚠️  httpx 未生成结果文件。")
        return []

    with open(httpx_output_file, 'r') as f:
        valid_urls = [line.strip() for line in f if line.strip()]

    print(f"[+] ✅ httpx 完成，发现 {len(valid_urls)} 个有效 Web 服务。")
    return valid_urls
# ===================================================


def run_muki(use_active, web_urls):
    if not web_urls:
        print("[!] ⚠️  无 Web 服务，跳过 muki。")
        return

    with open(muki_input_file, 'w') as f:
        for url in web_urls:
            f.write(url + '\n')

    muki_cmd = ['sudo', muki_exe, '-l', muki_input_file, '-N', '-t', '50']
    if not use_active:
        muki_cmd.append('-A')
    muki_cmd.extend(['-o', muki_output_file])

    print(f"\n[+] 🕵️  正在运行 muki（共 {len(web_urls)} 个目标）: {' '.join(muki_cmd)}")
    try:
        result = subprocess.run(muki_cmd)
        if result.returncode == 0:
            mode = "主动" if use_active else "被动"
            print(f"[+] ✅ muki ({mode}模式) 完成，结果保存至 '{muki_output_file}'")
        else:
            print("[!] ❌ muki 运行失败。")
    except KeyboardInterrupt:
        print("\n[!] 用户中断 muki")
        exit(1)


def save_final_results(run_muki_flag):
    web_targets = set()
    if os.path.exists(httpx_output_file):
        with open(httpx_output_file, 'r') as f:
            for line in f:
                url = line.strip()
                if url.startswith('http://'):
                    ip = url[7:].split(':')[0]
                elif url.startswith('https://'):
                    ip = url[8:].split(':')[0]
                else:
                    continue
                web_targets.add(ip)

    with open(final_output_file, 'w') as fw:
        for line in nmap_results:
            parts = line.strip().split(':', 2)
            if len(parts) == 3:
                ip, port, service = parts
                if run_muki_flag and ip in web_targets:
                    line = f"{ip}:{port}:{service} [MUKI]"
            fw.write(line + '\n')
    print(f"\n[+] 💾 最终结果已保存至 '{final_output_file}'")


def cleanup_temp_files():
    files_to_remove = [
        masscan_file, httpx_ip_file, httpx_output_file, muki_input_file
    ]
    for file_path in files_to_remove:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"[+] 🧹 已清理临时文件: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"[!] 无法删除 {file_path}: {e}")


def run_ping_scan():
    command = ['sudo', 'nmap', '-sn', '-iL', ip_file, '-oG', '-']
    print('\n🔄 正在执行 IP 存活检测 (nmap -sn)...\n', ' '.join(command))
    
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print("[!] ❌ nmap 存活检测失败。")
            exit(1)
        
        alive_ips = []
        for line in result.stdout.splitlines():
            if line.startswith('Host: ') and 'Status: Up' in line:
                ip = line.split()[1]
                alive_ips.append(ip)
        
        with open(ping_output_file, 'w') as f:
            for ip in alive_ips:
                f.write(ip + '\n')
        
        print(f"[+] ✅ 存活检测完成，共发现 {len(alive_ips)} 个存活主机。")
        print(f"[+] 💾 结果已保存至 '{ping_output_file}'")

    except KeyboardInterrupt:
        print("\n[!] 用户中断存活检测")
        exit(1)


def main():
    print("🚀 欢迎使用 mamap - masscan + nmap + httpx + muki 自动化工具\n")

    port_range, is_ping_mode = select_ports()
    if is_ping_mode:
        print("\n🎯 配置确认:")
        print("  - 扫描类型: IP 存活检测（Ping Scan）")
        input("\n👉 按回车键开始执行...")
        run_ping_scan()
    else:
        rate = select_rate()
        muki_mode = select_muki_mode()
        print("\n🎯 配置确认:")
        print(f"  - 扫描端口: {port_range}")
        print(f"  - 扫描速率: {rate} 包/秒")
        if muki_mode is None:
            print("  - muki 指纹识别: ❌ 不使用")
        else:
            mode_str = "主动（不加 -A）" if muki_mode else "被动（加 -A）"
            print(f"  - muki 指纹识别: ✅ {mode_str}")
        input("\n👉 按回车键开始执行...")

        run_masscan(port_range, rate)
        ip_ports = load_ip_ports()
        if not ip_ports:
            return

        run_nmap(ip_ports)

        web_urls = run_httpx()  # ✅ 使用 ./httpx -l ips.txt

        if muki_mode is not None:
            run_muki(muki_mode, web_urls)
            save_final_results(run_muki_flag=True)
        else:
            save_final_results(run_muki_flag=False)

        cleanup_temp_files()


if __name__ == '__main__':
    start_time = datetime.datetime.now()
    try:
        main()
    finally:
        _reset_terminal()
    
    end_time = datetime.datetime.now()
    elapsed = (end_time - start_time).total_seconds()
    print(f"\n✅ 全部任务完成！共处理 {total_ports} 个端口，耗时 {elapsed:.2f} 秒。")
    if os.path.exists(muki_output_file):
        print(f"📁 详细指纹结果: {muki_output_file}")
    print(f"📄 主报告文件: {final_output_file}")
    if os.path.exists(ping_output_file):
        print(f"🌐 存活主机列表: {ping_output_file}")
