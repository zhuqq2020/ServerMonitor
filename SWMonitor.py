import subprocess
import concurrent.futures
import time
import re
import platform
import configparser
import os
import logging
import csv
import chardet

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("ping_monitor.log"),  # 日志写入文件
        logging.StreamHandler()  # 日志输出到控制台
    ]
)

# 从配置文件中读取配置
def load_config(filename):
    config = configparser.ConfigParser()
    # 使用 utf-8-sig 编码读取文件，自动处理 BOM
    with open(filename, "r", encoding="utf-8-sig") as f:
        config.read_file(f)
    return config

# 检测文件编码
def detect_file_encoding(filename):
    with open(filename, "rb") as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        return result.get("encoding", "utf-8")

# 从当前目录下的 iplist.csv 文件中读取主机名称和 IP 地址
def load_ips_from_csv(filename):
    ip_list = []
    try:
        # 检测文件编码
        encoding = detect_file_encoding(filename)
        with open(filename, "r", encoding=encoding) as file:
            reader = csv.DictReader(file)
            for row in reader:
                hostname = row.get("主机名称")
                ip = row.get("IP地址")
                if hostname and ip:
                    ip_list.append((hostname, ip))
        return ip_list
    except Exception as e:
        logging.error(f"读取文件 {filename} 时发生错误: {e}")
        return []

# 调用 PushBot.exe 进行消息推送
def call_bot_exe(platform_name, message):
    if platform.system() == "Windows":
        # Windows 环境：调用 PushBot.exe
        bot_exe = "PushBot.exe"
    else:
        # 非 Windows 环境：调用 PushBot
        bot_exe = "./PushBot"

    # 检查 PushBot 程序是否存在
    if not os.path.exists(bot_exe):
        logging.error(f"找不到 {bot_exe}，请将 {bot_exe} 程序放至本程序目录后再重新运行本程序。")
        return  # 退出，不再尝试调用 PushBot

    # 构建命令
    command = [bot_exe, platform_name, message]

    try:
        # 执行命令
        subprocess.run(command, check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info(f"{platform_name} 消息已推送成功!")
    except subprocess.CalledProcessError as e:
        logging.error(f"调用 {bot_exe} 时出错: {e}")
    except Exception as e:
        logging.exception(f"执行过程中发生异常: {e}")

# 推送告警消息
def send_alert(alert_list, platforms):
    if not alert_list:
        return  # 如果没有告警，直接返回

    # 动态计算列宽
    hostname_width = max(len("设备名称"), max(len(hostname) for hostname, _, _ in alert_list))
    ip_width = max(len("设备IP地址"), max(len(ip) for _, ip, _ in alert_list))
    count_width = max(len("监测失败次数"), max(len(str(count)) for _, _, count in alert_list))

    # 构造推送消息模板
    message = "本次监控系统检测到以下设备不可达，请及时检查：\n"
    message += "-" * (hostname_width + ip_width + count_width + 35) + "\n"
    message += (
        f"{'设备名称'.ljust(hostname_width)}  "
        f"{'设备IP地址'.ljust(ip_width)}  "
        f"{'监测失败次数'.center(count_width)}\n"
    )
    message += "-" * (hostname_width + ip_width + count_width + 35) + "\n"
    for hostname, ip, failure_count in alert_list:
        message += (
            f"{hostname.ljust(hostname_width)}  "
            f"{ip.ljust(ip_width)}  "
            f"{str(failure_count).center(count_width)}\n"
        )
    message += "-" * (hostname_width + ip_width + count_width + 35) + "\n"
    message += f"告警时间：{time.strftime('%Y-%m-%d %H:%M:%S')}"

    # 根据启用的推送平台调用 PushBot
    for platform_name in platforms:
        call_bot_exe(platform_name, message)

def ping_ip(ip, ping_count, ping_timeout):
    # 根据操作系统选择 ping 命令参数
    if platform.system().lower() == "windows":
        ping_args = ["ping", "-n", str(ping_count), "-w", str(ping_timeout), ip]
    else:
        ping_args = ["ping", "-c", str(ping_count), "-W", str(ping_timeout // 1000), ip]

    # 使用 ping 命令检测 IP 是否可达
    result = subprocess.run(ping_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout

    # 解析 ping 的输出
    reachable = result.returncode == 0
    details = {}

    if reachable:
        # 提取响应时间
        if platform.system().lower() == "windows":
            time_matches = re.findall(r"时间=(\d+)ms", output)  # Windows 格式
        else:
            time_matches = re.findall(r"time=([\d.]+) ms", output)  # Linux/macOS 格式

        if time_matches:
            response_times = [float(t) for t in time_matches]
            details["response_time"] = int(sum(response_times) / len(response_times))  # 平均响应时间（取整）
        else:
            details["response_time"] = "未知"

        # 提取 TTL
        if platform.system().lower() == "windows":
            ttl_match = re.search(r"TTL=(\d+)", output)  # Windows 格式
        else:
            ttl_match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)  # Linux/macOS 格式

        if ttl_match:
            details["ttl"] = int(ttl_match.group(1))  # TTL 值
        else:
            details["ttl"] = "未知"

    return ip, reachable, details

def monitor_ips(ip_list, platforms, ping_count, ping_timeout, failure_threshold):
    # 使用全局变量记录每个 IP 的失败次数（跨监测周期）
    if not hasattr(monitor_ips, "failure_count"):
        monitor_ips.failure_count = {ip: 0 for _, ip in ip_list}

    alert_list = []  # 用于存储需要告警的主机信息

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # 并发执行 Ping 操作
        future_to_host = {
            executor.submit(ping_ip, ip, ping_count, ping_timeout): (hostname, ip)
            for hostname, ip in ip_list
        }

        for future in concurrent.futures.as_completed(future_to_host):
            hostname, ip = future_to_host[future]
            try:
                ip, reachable, details = future.result()
                if not reachable:
                    monitor_ips.failure_count[ip] += 1
                    if monitor_ips.failure_count[ip] >= failure_threshold:
                        # 日志中显示的失败次数为累计值
                        logged_failure_count = monitor_ips.failure_count[ip]
                        logging.warning(
                            f"主机 {hostname} (IP: {ip}) 不可达（监测失败次数: {logged_failure_count}）"
                        )
                        # 将告警主机添加到告警列表
                        alert_list.append((hostname, ip, logged_failure_count))
                else:
                    # 如果可达，重置失败次数
                    monitor_ips.failure_count[ip] = 0
                    # 记录成功信息
                    response_time = details.get("response_time", "未知")
                    ttl = details.get("ttl", "未知")
                    logging.info(f"主机 {hostname} (IP: {ip}) 可达 - 响应时间: {response_time}ms, TTL: {ttl}")
            except Exception as e:
                logging.error(f"Ping 主机 {hostname} (IP: {ip}) 时发生错误: {e}")

    # 如果有告警主机，推送告警消息
    if alert_list:
        send_alert(alert_list, platforms)

def main():
    # 清空日志文件
    with open("ping_monitor.log", "w") as log_file:
        log_file.write("")  # 清空文件内容

    # 加载配置文件
    config = load_config("config.conf")

    # 读取检测间隔
    interval = int(config.get("settings", "interval", fallback=300))  # 默认 300 秒

    # 读取启用的推送平台
    platforms = config.get("platforms", "enabled", fallback="").strip('[]').replace('"', '').replace("'", '').split(",")
    platforms = [platform.strip() for platform in platforms if platform.strip()]

    # 读取 Ping 配置
    ping_count = int(config.get("ping", "ping_count", fallback=3))  # 默认 Ping 3 次
    ping_timeout = int(config.get("ping", "ping_timeout", fallback=1000))  # 默认超时 1000 毫秒
    failure_threshold = int(config.get("ping", "failure_threshold", fallback=3))  # 默认监测失败 2 次触发告警

    # 从 iplist.csv 文件中加载主机名称和 IP 列表
    ip_list = load_ips_from_csv("iplist.csv")
    if not ip_list:
        logging.error("iplist.csv 文件中没有有效的主机名称和 IP 地址。")
        return

    # 循环监测
    while True:
        logging.info(f"开始新一轮监测，时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        monitor_ips(ip_list, platforms, ping_count, ping_timeout, failure_threshold)
        logging.info(f"监测完成，等待 {interval} 秒...")
        time.sleep(interval)  # 根据配置的间隔时间等待

if __name__ == "__main__":
    main()