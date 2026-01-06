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
process_num = 50

# 创建 result 目录
result_dir = "result"
os.makedirs(result_dir, exist_ok=True)

# 生成带时间戳的文件路径
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
masscan_file = os.path.join(result_dir, f"masscan_{timestamp}.json")
muki_input_file = os.path.join(result_dir, f"muki_targets_{timestamp}.txt")
muki_output_file = os.path.join(result_dir, f"muki_results_{timestamp}.xlsx")
final_output_file = os.path.join(result_dir, f"services_{timestamp}.txt")

# ========== 新增：存活检测端口 ==========
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
    print("3) 存活检测（21,22,53,80,443,445,1433,3306,3389,8080）")
    while True:
        choice = input("请选择扫描端口范围 (1/2/3): ").strip()
        if choice == '1':
            return '1-65535'
        elif choice == '2':
            return RCE_PORTS_STR
        elif choice == '3':
            return ALIVE_PORTS_STR
        else:
            print("❌ 请输入 1、2 或 3。")


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
        choice = input("是否对 HTTP/HTTPS 服务使用 muki 进行指纹识别？(y/n): ").strip().lower()
        if choice in ['n', 'no']:
            return None
        elif choice in ['y', 'yes']:
            while True:
                active = input("  是否启用主动探测（会发送额外请求）？(y/n): ").strip().lower()
                if active in ['y', 'yes']:
                    return True   # 主动 → 不加 -A
                elif active in ['n', 'no']:
                    return False  # 被动 → 加 -A
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


def run_muki(use_active):
    http_list = []
    for line in nmap_results:
        parts = line.strip().split(':', 2)
        if len(parts) != 3:
            continue
        ip, port, service = parts
        service_lower = service.lower()
        if 'http' in service_lower:
            proto = 'https' if 'https' in service_lower else 'http'
            url = f"{proto}://{ip}:{port}"
            http_list.append(url)

    if not http_list:
        print("[!] ⚠️  未发现 HTTP/HTTPS 服务，跳过 muki。")
        return

    with open(muki_input_file, 'w') as f:
        for url in http_list:
            f.write(url + '\n')

    # 添加 -t 50 并发参数
    muki_cmd = ['sudo', muki_exe, '-l', muki_input_file, '-N', '-t', '50']
    if not use_active:
        muki_cmd.append('-A')
    muki_cmd.extend(['-o', muki_output_file])

    print(f"\n[+] 🕵️  正在运行 muki: {' '.join(muki_cmd)}")
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
    with open(final_output_file, 'w') as fw:
        for line in nmap_results:
            parts = line.strip().split(':', 2)
            if len(parts) == 3:
                ip, port, service = parts
                if run_muki_flag and 'http' in service.lower():
                    line = f"{ip}:{port}:{service} [MUKI]"
            fw.write(line + '\n')
    print(f"\n[+] 💾 最终结果已保存至 '{final_output_file}'")


def cleanup_temp_files():
    """删除临时文件，仅保留最终结果"""
    files_to_remove = [masscan_file, muki_input_file]
    for file_path in files_to_remove:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"[+] 🧹 已清理临时文件: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"[!] 无法删除 {file_path}: {e}")


def main():
    print("🚀 欢迎使用 mamap - masscan + nmap + muki 自动化工具\n")

    port_range = select_ports()
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

    if muki_mode is not None:
        run_muki(muki_mode)
        save_final_results(run_muki_flag=True)
    else:
        save_final_results(run_muki_flag=False)

    # 清理临时文件
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
    print(f"📁 详细指纹结果: {muki_output_file}")
    print(f"📄 主报告文件: {final_output_file}")
