#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          SERVER SECURITY SCANNER v2.0                        ║
║  Порты · Сервисы · Уязвимости · Поиск эксплойтов           ║
╚══════════════════════════════════════════════════════════════╝

Использование:
    python security_scanner.py --target 192.168.1.1
    python security_scanner.py --target example.com --ports 1-1024
    python security_scanner.py --target 10.0.0.1 --full --output report.json
    python security_scanner.py --target 10.0.0.1 --no-exploits   # без поиска эксплойтов
"""

import socket
import ssl
import json
import argparse
import ipaddress
import concurrent.futures
import datetime
import sys
import re
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

# ─────────────────────────────────────────────
# ЦВЕТА
# ─────────────────────────────────────────────
class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def c(color, text):
    return f"{color}{text}{Colors.RESET}"

def banner():
    print(c(Colors.CYAN, r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║   ███████╗███████╗ ██████╗    ███████╗ ██████╗ █████╗ ███╗  ║
  ║   ██╔════╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗ ║
  ║   ███████╗█████╗  ██║         ███████╗██║     ███████║██╔██╗ ║
  ║   ╚════██║██╔══╝  ██║         ╚════██║██║     ██╔══██║██║╚██╗║
  ║   ███████║███████╗╚██████╗    ███████║╚██████╗██║  ██║██║ ╚█║
  ║   ╚══════╝╚══════╝ ╚═════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚║
  ║      SERVER SECURITY SCANNER v2.1  [Service Detect + Exploits]║
  ╚══════════════════════════════════════════════════════════════╝
"""))
    print(c(Colors.DIM, f"  Запуск: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"))


# ─────────────────────────────────────────────
# ИЗВЕСТНЫЕ ПОРТЫ
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 512: "rexec",
    513: "rlogin", 514: "rsh", 587: "SMTP Submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS Proxy",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS",
    2181: "ZooKeeper", 2375: "Docker (незащищённый)", 2376: "Docker TLS",
    3000: "Grafana/Dev", 3306: "MySQL/MariaDB", 3389: "RDP",
    4369: "Erlang/RabbitMQ", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 6379: "Redis", 6443: "Kubernetes API",
    7001: "WebLogic", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    8888: "Jupyter Notebook", 9000: "SonarQube/PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch HTTP",
    9300: "Elasticsearch Transport", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB Shard", 50000: "SAP",
}

TOP_100_PORTS = sorted(list(COMMON_PORTS.keys()) + [
    8000, 8008, 8009, 8081, 8082, 8083, 8084, 8085, 8086, 8090,
    9100, 9999, 10000, 10250, 15672, 16379, 26379, 27019,
])

SEVERITY_COLOR = {
    "CRITICAL": Colors.RED,
    "HIGH":     Colors.MAGENTA,
    "MEDIUM":   Colors.YELLOW,
    "LOW":      Colors.BLUE,
    "INFO":     Colors.CYAN,
    "OK":       Colors.GREEN,
}

# ─────────────────────────────────────────────
# БАЗА CVE / ЭКСПЛОЙТОВ ПО СЕРВИСАМ И ВЕРСИЯМ
# ─────────────────────────────────────────────
# Формат: keyword -> [ {cve, cvss, описание, ссылка на exploit} ]
EXPLOIT_DB: dict = {
    "redis": [
        {
            "cve": "CVE-2022-0543",
            "cvss": 10.0,
            "title": "Redis Lua Sandbox Escape / RCE",
            "description": "Уязвимость в Lua-интерпретаторе Redis позволяет выполнить произвольный код через eval.",
            "edb_id": "50608",
            "url": "https://www.exploit-db.com/exploits/50608",
            "type": "Remote Code Execution",
            "affected": "Redis < 6.2.6, < 7.0",
        },
        {
            "cve": "CVE-2015-8080",
            "cvss": 7.5,
            "title": "Redis Integer Overflow → RCE",
            "description": "Переполнение целого числа в функции getnum() приводит к выполнению кода.",
            "edb_id": "38738",
            "url": "https://www.exploit-db.com/exploits/38738",
            "type": "Remote Code Execution",
            "affected": "Redis < 3.0.7",
        },
        {
            "cve": "N/A",
            "cvss": 9.0,
            "title": "Redis Unauthenticated RCE через CONFIG SET",
            "description": "Без пароля атакующий может записать SSH-ключи или cron-задачи через CONFIG SET dir/dbfilename.",
            "edb_id": "47195",
            "url": "https://www.exploit-db.com/exploits/47195",
            "type": "Unauthenticated RCE",
            "affected": "Redis без requirepass",
        },
    ],
    "mongodb": [
        {
            "cve": "N/A",
            "cvss": 9.8,
            "title": "MongoDB Unauthenticated Access",
            "description": "MongoDB без включённой аутентификации — полный доступ к данным без логина.",
            "edb_id": "N/A",
            "url": "https://www.shodan.io/search?query=product%3AMongoDB",
            "type": "Unauthenticated Access",
            "affected": "MongoDB без --auth",
        },
        {
            "cve": "CVE-2019-2386",
            "cvss": 7.1,
            "title": "MongoDB Use-After-Free in Aggregation",
            "description": "Use-after-free уязвимость в агрегационном движке MongoDB.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2386",
            "type": "Denial of Service / Memory Corruption",
            "affected": "MongoDB < 4.0.12, < 4.2.3",
        },
    ],
    "smb": [
        {
            "cve": "CVE-2017-0144",
            "cvss": 9.3,
            "title": "EternalBlue — MS17-010 SMB RCE",
            "description": "Легендарный эксплойт АНБ. Используется WannaCry/NotPetya. Удалённое выполнение кода через SMBv1.",
            "edb_id": "42315",
            "url": "https://www.exploit-db.com/exploits/42315",
            "type": "Remote Code Execution (Wormable)",
            "affected": "Windows XP–Server 2008 R2 без патча MS17-010",
        },
        {
            "cve": "CVE-2020-0796",
            "cvss": 10.0,
            "title": "SMBGhost — SMBv3 RCE (без аутентификации)",
            "description": "Переполнение буфера в SMBv3. Удалённое выполнение кода без аутентификации.",
            "edb_id": "48267",
            "url": "https://www.exploit-db.com/exploits/48267",
            "type": "Remote Code Execution",
            "affected": "Windows 10 1903/1909, Server 1903/1909",
        },
        {
            "cve": "CVE-2021-44142",
            "cvss": 9.9,
            "title": "Samba Heap Out-of-Bounds RCE",
            "description": "Запись за пределы кучи в обработчике VFS приводит к RCE.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44142",
            "type": "Remote Code Execution",
            "affected": "Samba < 4.13.17, < 4.14.12, < 4.15.5",
        },
    ],
    "rdp": [
        {
            "cve": "CVE-2019-0708",
            "cvss": 9.8,
            "title": "BlueKeep — RDP Pre-Auth RCE",
            "description": "Критическая уязвимость в RDP без аутентификации. Позволяет выполнить код на уровне SYSTEM.",
            "edb_id": "47416",
            "url": "https://www.exploit-db.com/exploits/47416",
            "type": "Remote Code Execution (Pre-Auth)",
            "affected": "Windows XP, 7, Server 2003/2008 без обновлений",
        },
        {
            "cve": "CVE-2019-1181",
            "cvss": 9.8,
            "title": "DejaBlue — RDP RCE",
            "description": "Семейство уязвимостей RDP — аналог BlueKeep для новых версий Windows.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1181",
            "type": "Remote Code Execution",
            "affected": "Windows 7–10, Server 2008–2019",
        },
    ],
    "ssh": [
        {
            "cve": "CVE-2023-38408",
            "cvss": 9.8,
            "title": "OpenSSH ssh-agent Remote Code Execution",
            "description": "RCE через злонамеренный SSH-агент при использовании agent forwarding.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38408",
            "type": "Remote Code Execution",
            "affected": "OpenSSH < 9.3p2",
        },
        {
            "cve": "CVE-2024-6387",
            "cvss": 8.1,
            "title": "regreSSHion — OpenSSH Unauthenticated RCE",
            "description": "Race condition в обработчике сигналов. Позволяет получить root-доступ без аутентификации (сложная атака).",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387",
            "type": "Remote Code Execution (Pre-Auth)",
            "affected": "OpenSSH 8.5p1 – 9.7p1",
        },
        {
            "cve": "CVE-2016-6210",
            "cvss": 5.0,
            "title": "OpenSSH User Enumeration",
            "description": "Различие во времени ответа позволяет перебирать существующих пользователей.",
            "edb_id": "40136",
            "url": "https://www.exploit-db.com/exploits/40136",
            "type": "User Enumeration",
            "affected": "OpenSSH < 7.3",
        },
    ],
    "ftp": [
        {
            "cve": "CVE-2011-2523",
            "cvss": 10.0,
            "title": "vsftpd 2.3.4 Backdoor RCE",
            "description": "Бэкдор в vsftpd 2.3.4. При отправке ':)' в имени пользователя открывает шелл на порту 6200.",
            "edb_id": "17491",
            "url": "https://www.exploit-db.com/exploits/17491",
            "type": "Backdoor / Remote Code Execution",
            "affected": "vsftpd 2.3.4",
        },
        {
            "cve": "CVE-2010-4221",
            "cvss": 10.0,
            "title": "ProFTPD 1.3.2rc3 < 1.3.3b Telnet IAC Stack Overflow",
            "description": "Переполнение стека через Telnet IAC команды в ProFTPD.",
            "edb_id": "15449",
            "url": "https://www.exploit-db.com/exploits/15449",
            "type": "Remote Code Execution",
            "affected": "ProFTPD 1.3.2rc3 – 1.3.3b",
        },
    ],
    "elasticsearch": [
        {
            "cve": "CVE-2014-3120",
            "cvss": 7.5,
            "title": "Elasticsearch Dynamic Script RCE",
            "description": "Выполнение произвольного кода через динамические Groovy/MVEL скрипты.",
            "edb_id": "33370",
            "url": "https://www.exploit-db.com/exploits/33370",
            "type": "Remote Code Execution",
            "affected": "Elasticsearch < 1.3.8, < 1.4.3",
        },
        {
            "cve": "CVE-2015-1427",
            "cvss": 10.0,
            "title": "Elasticsearch Groovy Sandbox Escape RCE (Shellshock for ES)",
            "description": "Groovy sandbox escape позволяет выполнить системные команды.",
            "edb_id": "36337",
            "url": "https://www.exploit-db.com/exploits/36337",
            "type": "Remote Code Execution",
            "affected": "Elasticsearch 1.3.0–1.3.7, 1.4.0–1.4.2",
        },
    ],
    "docker": [
        {
            "cve": "CVE-2019-5736",
            "cvss": 8.6,
            "title": "runc Container Escape",
            "description": "Позволяет контейнеру перезаписать бинарник runc на хосте и получить root-доступ.",
            "edb_id": "46369",
            "url": "https://www.exploit-db.com/exploits/46369",
            "type": "Container Escape",
            "affected": "Docker < 18.09.2, runc < 1.0-rc6",
        },
        {
            "cve": "N/A",
            "cvss": 10.0,
            "title": "Docker API Unauthenticated Access → Host RCE",
            "description": "Открытый Docker API (порт 2375) даёт полный контроль над хостом: запуск привилегированных контейнеров, монтирование /.",
            "edb_id": "N/A",
            "url": "https://docs.docker.com/engine/security/protect-access/",
            "type": "Unauthenticated RCE",
            "affected": "Docker с открытым TCP сокетом без TLS",
        },
    ],
    "apache": [
        {
            "cve": "CVE-2021-41773",
            "cvss": 7.5,
            "title": "Apache HTTP Server Path Traversal & RCE",
            "description": "Path traversal в Apache 2.4.49 позволяет читать файлы вне DocumentRoot и выполнять CGI-скрипты.",
            "edb_id": "50383",
            "url": "https://www.exploit-db.com/exploits/50383",
            "type": "Path Traversal / RCE",
            "affected": "Apache 2.4.49",
        },
        {
            "cve": "CVE-2021-42013",
            "cvss": 9.8,
            "title": "Apache HTTP Server Path Traversal & RCE (bypass)",
            "description": "Обход патча CVE-2021-41773 через двойное URL-кодирование.",
            "edb_id": "50406",
            "url": "https://www.exploit-db.com/exploits/50406",
            "type": "Path Traversal / RCE",
            "affected": "Apache 2.4.50",
        },
        {
            "cve": "CVE-2017-7679",
            "cvss": 9.8,
            "title": "Apache mod_mime Buffer Overread",
            "description": "Чтение за пределами буфера в mod_mime при обработке Content-Type.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7679",
            "type": "Buffer Overread / DoS",
            "affected": "Apache < 2.2.33, < 2.4.26",
        },
    ],
    "nginx": [
        {
            "cve": "CVE-2021-23017",
            "cvss": 7.7,
            "title": "nginx DNS Resolver Off-By-One Heap Write",
            "description": "Off-by-one ошибка в DNS-резолвере nginx. Может привести к выполнению кода.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017",
            "type": "Heap Corruption / Potential RCE",
            "affected": "nginx 0.6.18–1.20.0",
        },
    ],
    "mysql": [
        {
            "cve": "CVE-2012-2122",
            "cvss": 7.5,
            "title": "MySQL Authentication Bypass",
            "description": "Из-за ошибки в memcmp() можно войти в MySQL перебором пароля (в среднем 256 попыток).",
            "edb_id": "19092",
            "url": "https://www.exploit-db.com/exploits/19092",
            "type": "Authentication Bypass",
            "affected": "MySQL 5.1.x, 5.5.x < 5.5.24",
        },
        {
            "cve": "CVE-2016-6662",
            "cvss": 9.8,
            "title": "MySQL Remote Root Code Execution",
            "description": "Злонамеренный my.cnf файл позволяет выполнить код от имени root через mysqld.",
            "edb_id": "40360",
            "url": "https://www.exploit-db.com/exploits/40360",
            "type": "Remote Code Execution",
            "affected": "MySQL <= 5.7.14, MariaDB <= 10.1.17",
        },
    ],
    "telnet": [
        {
            "cve": "N/A",
            "cvss": 9.0,
            "title": "Telnet — передача данных в открытом виде",
            "description": "Все данные (логин, пароль, команды) передаются без шифрования. MITM-атака тривиальна.",
            "edb_id": "N/A",
            "url": "https://www.shodan.io/search?query=port%3A23",
            "type": "Cleartext Credentials",
            "affected": "Все реализации Telnet",
        },
    ],
    "vnc": [
        {
            "cve": "CVE-2006-2369",
            "cvss": 7.5,
            "title": "RealVNC Authentication Bypass",
            "description": "Выбор 'None' в качестве метода аутентификации позволяет войти без пароля.",
            "edb_id": "1791",
            "url": "https://www.exploit-db.com/exploits/1791",
            "type": "Authentication Bypass",
            "affected": "RealVNC 4.1.1",
        },
        {
            "cve": "CVE-2019-15681",
            "cvss": 7.5,
            "title": "LibVNCServer Memory Leak",
            "description": "Утечка памяти сервера через специально созданные запросы клиента.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15681",
            "type": "Memory Leak / Information Disclosure",
            "affected": "libvncserver < 0.9.13",
        },
    ],
    "snmp": [
        {
            "cve": "CVE-2002-0013",
            "cvss": 10.0,
            "title": "SNMP v1/v2c Multiple Vulnerabilities",
            "description": "Множественные переполнения буфера в SNMP v1/v2c при обработке community strings.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0013",
            "type": "Buffer Overflow / RCE",
            "affected": "SNMP v1, v2c реализации",
        },
    ],
    "weblogic": [
        {
            "cve": "CVE-2020-14882",
            "cvss": 9.8,
            "title": "WebLogic Console HTTP RCE (без аутентификации)",
            "description": "Обход аутентификации и выполнение кода через консоль управления WebLogic.",
            "edb_id": "49096",
            "url": "https://www.exploit-db.com/exploits/49096",
            "type": "Unauthenticated RCE",
            "affected": "WebLogic 10.3.6.0, 12.1.3.0, 12.2.1.3/4, 14.1.1.0",
        },
        {
            "cve": "CVE-2019-2725",
            "cvss": 9.8,
            "title": "WebLogic wls9_async Deserialization RCE",
            "description": "Небезопасная десериализация Java-объектов в wls9_async и wls-wsat компонентах.",
            "edb_id": "46780",
            "url": "https://www.exploit-db.com/exploits/46780",
            "type": "Remote Code Execution",
            "affected": "WebLogic 10.3.6, 12.1.3, 12.2.1",
        },
    ],
    "jupyter": [
        {
            "cve": "N/A",
            "cvss": 10.0,
            "title": "Jupyter Notebook без аутентификации — RCE",
            "description": "Jupyter без пароля/токена позволяет запускать произвольный Python-код на сервере прямо из браузера.",
            "edb_id": "N/A",
            "url": "https://jupyter-notebook.readthedocs.io/en/stable/security.html",
            "type": "Unauthenticated Remote Code Execution",
            "affected": "Jupyter Notebook без пароля",
        },
    ],
    "kubernetes": [
        {
            "cve": "CVE-2018-1002105",
            "cvss": 9.8,
            "title": "Kubernetes API Server Privilege Escalation",
            "description": "Через backend error response атакующий может эскалировать до cluster-admin.",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1002105",
            "type": "Privilege Escalation",
            "affected": "Kubernetes < 1.10.11, < 1.11.5, < 1.12.3",
        },
    ],
    "openssh": [
        # Повторно для banner matching
        {
            "cve": "CVE-2024-6387",
            "cvss": 8.1,
            "title": "regreSSHion — OpenSSH Unauthenticated RCE",
            "description": "Race condition в обработчике сигналов glibc. Pre-auth RCE от root (32-bitная рандомизация).",
            "edb_id": "N/A",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6387",
            "type": "Remote Code Execution (Pre-Auth)",
            "affected": "OpenSSH 8.5p1–9.7p1",
        },
    ],
}

# Маппинг: порт → ключ в EXPLOIT_DB
PORT_TO_EXPLOIT_KEY = {
    21:    ["ftp"],
    22:    ["ssh", "openssh"],
    23:    ["telnet"],
    445:   ["smb"],
    139:   ["smb"],
    3389:  ["rdp"],
    6379:  ["redis"],
    27017: ["mongodb"],
    9200:  ["elasticsearch"],
    9300:  ["elasticsearch"],
    2375:  ["docker"],
    2376:  ["docker"],
    80:    ["apache", "nginx"],
    8080:  ["apache", "nginx"],
    3306:  ["mysql"],
    5900:  ["vnc"],
    161:   ["snmp"],
    7001:  ["weblogic"],
    8888:  ["jupyter"],
    6443:  ["kubernetes"],
}


# ─────────────────────────────────────────────
# ОНЛАЙН-ПОИСК: CIRCL CVE API + ExploitDB
# ─────────────────────────────────────────────
def search_exploitdb_online(keyword: str, max_results: int = 3) -> list:
    """Поиск эксплойтов через Exploit-DB (cve.circl.lu API)."""
    results = []
    try:
        url = f"https://www.exploit-db.com/search?q={urllib.parse.quote(keyword)}&type=exploits&platform="
        # Используем публичный JSON API exploit-db
        api_url = f"https://exploit.kitploit.com/api/v1/search?q={urllib.parse.quote(keyword)}&limit={max_results}"
        req = urllib.request.Request(
            api_url,
            headers={"User-Agent": "SecurityScanner/2.0 (research purposes)"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            for item in data.get("results", [])[:max_results]:
                results.append({
                    "title": item.get("title", ""),
                    "url": f"https://www.exploit-db.com/exploits/{item.get('id', '')}",
                    "type": item.get("type", ""),
                    "date": item.get("date", ""),
                    "source": "exploit-db (online)",
                })
    except Exception:
        pass
    return results


def search_cve_online(keyword: str, max_results: int = 3) -> list:
    """Поиск CVE через CIRCL CVE Search API (бесплатный, без ключа)."""
    results = []
    try:
        api_url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(keyword)}"
        req = urllib.request.Request(
            api_url,
            headers={"User-Agent": "SecurityScanner/2.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
            entries = data if isinstance(data, list) else data.get("data", [])
            # Сортировать по CVSS (по убыванию)
            def get_cvss(e):
                try:
                    return float(e.get("cvss", 0) or 0)
                except Exception:
                    return 0.0
            entries_sorted = sorted(entries, key=get_cvss, reverse=True)
            for entry in entries_sorted[:max_results]:
                cve_id = entry.get("id", "")
                cvss = entry.get("cvss", "N/A")
                summary = entry.get("summary", "Нет описания.")[:200]
                results.append({
                    "cve": cve_id,
                    "cvss": cvss,
                    "title": summary[:80] + ("…" if len(summary) > 80 else ""),
                    "description": summary,
                    "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                    "source": "CIRCL CVE Search",
                    "type": "CVE",
                })
    except Exception:
        pass
    return results


def search_exploits_for_service(service_name: str, version: str = "", port: int = 0,
                                  online: bool = True) -> list:
    """
    Объединённый поиск эксплойтов:
    1) Встроенная база EXPLOIT_DB
    2) Онлайн CIRCL CVE API (если --no-exploits не задан)
    """
    found = []
    seen_cves = set()

    # 1. Встроенная база — по порту
    if port in PORT_TO_EXPLOIT_KEY:
        for key in PORT_TO_EXPLOIT_KEY[port]:
            for exploit in EXPLOIT_DB.get(key, []):
                cve = exploit.get("cve", "")
                if cve not in seen_cves:
                    seen_cves.add(cve)
                    found.append({**exploit, "source": "local-db"})

    # 2. Встроенная база — по имени сервиса
    svc_lower = service_name.lower()
    for key, exploits in EXPLOIT_DB.items():
        if key in svc_lower or svc_lower in key:
            for exploit in exploits:
                cve = exploit.get("cve", "")
                if cve not in seen_cves:
                    seen_cves.add(cve)
                    found.append({**exploit, "source": "local-db"})

    # 3. Онлайн поиск CVE по имени сервиса + версии
    if online:
        query = f"{service_name} {version}".strip()
        online_cves = search_cve_online(query, max_results=3)
        for item in online_cves:
            cve = item.get("cve", "")
            if cve and cve not in seen_cves:
                seen_cves.add(cve)
                found.append(item)

    # Сортировка по CVSS
    def cvss_key(e):
        try:
            return float(e.get("cvss", 0) or 0)
        except Exception:
            return 0.0

    return sorted(found, key=cvss_key, reverse=True)


# ─────────────────────────────────────────────
# ОПРЕДЕЛЕНИЕ СЕРВИСА И ВЕРСИИ (Protocol Probing)
# ─────────────────────────────────────────────

# Пробы для каждого протокола: (запрос, regex для версии, имя сервиса)
PROTOCOL_PROBES = [
    # HTTP
    {
        "name": "HTTP",
        "request": b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "match": re.compile(rb"HTTP/[\d.]+\s+(\d+)"),
        "version_re": re.compile(
            rb"(?:Server|X-Powered-By):\s*([^\r\n]{1,60})", re.IGNORECASE
        ),
        "ports": set(range(1, 65536)),  # универсальный — пробуем на любом
    },
    # SSH
    {
        "name": "SSH",
        "request": b"",
        "match": re.compile(rb"SSH-"),
        "version_re": re.compile(rb"SSH-[\d.]+-([^\r\n]{1,50})"),
        "ports": set(),
    },
    # FTP
    {
        "name": "FTP",
        "request": b"",
        "match": re.compile(rb"^220[- ]"),
        "version_re": re.compile(rb"220[- ]([^\r\n]{1,60})"),
        "ports": set(),
    },
    # SMTP
    {
        "name": "SMTP",
        "request": b"",
        "match": re.compile(rb"^220[- ].*[Ss][Mm][Tt][Pp]"),
        "version_re": re.compile(rb"220[- ]([^\r\n]{1,60})"),
        "ports": set(),
    },
    # POP3
    {
        "name": "POP3",
        "request": b"",
        "match": re.compile(rb"^\+OK"),
        "version_re": re.compile(rb"\+OK ([^\r\n]{1,50})"),
        "ports": set(),
    },
    # IMAP
    {
        "name": "IMAP",
        "request": b"",
        "match": re.compile(rb"^\* OK"),
        "version_re": re.compile(rb"\* OK ([^\r\n]{1,60})"),
        "ports": set(),
    },
    # Redis
    {
        "name": "Redis",
        "request": b"PING\r\n",
        "match": re.compile(rb"\+PONG|\-ERR|\-NOAUTH"),
        "version_re": re.compile(rb"redis_version:([\d.]+)", re.IGNORECASE),
        "ports": set(),
        "extra_request": b"INFO server\r\n",
    },
    # MySQL/MariaDB
    {
        "name": "MySQL",
        "request": b"",
        "match": re.compile(rb"[\x00-\xff]{4}[\x0a\x09]"),
        "version_re": re.compile(rb"[\x00-\xff]{5}([\d]+\.[\d]+\.[\d]+[^\x00]*)"),
        "ports": {3306},
    },
    # MongoDB
    {
        "name": "MongoDB",
        "request": b"\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x17\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",
        "match": re.compile(rb"ismaster|maxBsonObjectSize", re.IGNORECASE),
        "version_re": re.compile(rb"maxWireVersion"),
        "ports": {27017, 27018},
    },
    # Memcached
    {
        "name": "Memcached",
        "request": b"version\r\n",
        "match": re.compile(rb"^VERSION"),
        "version_re": re.compile(rb"VERSION ([\d.]+)"),
        "ports": {11211},
    },
    # RDP (ТPKT / X.224)
    {
        "name": "RDP",
        "request": bytes.fromhex("030000130ee000000000000100080003000000"),
        "match": re.compile(rb"\x03\x00"),
        "version_re": None,
        "ports": {3389},
    },
    # VNC
    {
        "name": "VNC",
        "request": b"",
        "match": re.compile(rb"RFB [\d]+\.[\d]+"),
        "version_re": re.compile(rb"RFB ([\d]+\.[\d]+)"),
        "ports": set(),
    },
    # SMB
    {
        "name": "SMB",
        "request": bytes.fromhex(
            "000000850000010066534d4271000000001843c800000000000000000000000000000000"
            "fffffe000000000000000000000000000000000000000000"
        ),
        "match": re.compile(rb"\xffSMB|\xfeSMB"),
        "version_re": None,
        "ports": {445, 139},
    },
    # PostgreSQL
    {
        "name": "PostgreSQL",
        "request": bytes.fromhex("000000080000000004d2162f"),
        "match": re.compile(rb"[NS](?:\x00|$)"),
        "version_re": None,
        "ports": {5432},
    },
    # Elasticsearch
    {
        "name": "Elasticsearch",
        "request": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "match": re.compile(rb"tagline|lucene_version|elasticsearch", re.IGNORECASE),
        "version_re": re.compile(rb"number['\"]?\s*:\s*['\"]([\d.]+)", re.IGNORECASE),
        "ports": {9200},
    },
    # Docker API
    {
        "name": "Docker API",
        "request": b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "match": re.compile(rb"ApiVersion|DockerRootDir", re.IGNORECASE),
        "version_re": re.compile(rb"Version['\"]?\s*:\s*['\"]([\d.]+)", re.IGNORECASE),
        "ports": {2375, 2376},
    },
]


def detect_service_and_version(host: str, port: int, timeout: float = 2.0) -> dict:
    """
    Определить сервис и версию на порту через protocol probing.
    Возвращает dict: service, version, banner, raw_banner
    """
    result = {
        "service":    COMMON_PORTS.get(port, "Unknown"),
        "version":    "",
        "banner":     "",
        "raw_banner": b"",
        "ssl":        False,
    }

    # Сначала попробуем SSL/TLS — многие сервисы на нестандартных портах
    ssl_info = try_ssl_probe(host, port, timeout)
    if ssl_info:
        result["ssl"] = True
        result["banner"] = ssl_info["banner"]
        if ssl_info.get("service"):
            result["service"] = ssl_info["service"]
        if ssl_info.get("version"):
            result["version"] = ssl_info["version"]
        # Поверх SSL — тоже попробуем HTTP
        http_over_ssl = try_http_probe_ssl(host, port, timeout)
        if http_over_ssl:
            result["service"] = http_over_ssl["service"]
            result["version"] = http_over_ssl["version"]
            result["banner"]  = http_over_ssl["banner"] + " | " + result["banner"]
        return result

    # Попробуем каждый протокол
    # Стратегия: сначала порт-специфичные пробы, потом универсальные
    port_specific = [p for p in PROTOCOL_PROBES if port in p["ports"] and p["ports"]]
    generic      = [p for p in PROTOCOL_PROBES if not p["ports"]]
    http_probe   = [p for p in PROTOCOL_PROBES if p["name"] == "HTTP"]

    order = port_specific + generic + http_probe

    for probe in order:
        detected = try_probe(host, port, probe, timeout)
        if detected:
            result["service"] = detected["service"]
            result["version"] = detected["version"]
            result["banner"]  = detected["banner"]
            result["raw_banner"] = detected.get("raw", b"")
            return result

    # Финальный fallback — просто прочитать что пришло
    raw = raw_read(host, port, timeout)
    if raw:
        result["banner"] = raw.decode("utf-8", errors="replace").strip()[:200]
        result["raw_banner"] = raw

    return result


def try_probe(host: str, port: int, probe: dict, timeout: float) -> Optional[dict]:
    """Попытаться идентифицировать сервис одной пробой."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Отправить запрос (если есть)
        if probe["request"]:
            sock.send(probe["request"])

        time.sleep(0.2)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        except Exception:
            pass

        # Для Redis — дополнительный запрос INFO
        if probe["name"] == "Redis" and probe.get("extra_request") and data:
            try:
                sock.send(probe["extra_request"])
                time.sleep(0.3)
                data2 = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data2 += chunk
                    if len(data2) > 4096:
                        break
                data += data2
            except Exception:
                pass

        sock.close()

        if not data:
            return None

        # Проверить совпадение
        if probe["match"] and not probe["match"].search(data):
            return None

        service = probe["name"]
        version = ""
        if probe.get("version_re"):
            m = probe["version_re"].search(data)
            if m:
                try:
                    version = m.group(1).decode("utf-8", errors="replace").strip()
                except Exception:
                    version = str(m.group(1))

        banner = data.decode("utf-8", errors="replace").strip()[:300]
        return {"service": service, "version": version, "banner": banner, "raw": data}

    except Exception:
        return None


def try_ssl_probe(host: str, port: int, timeout: float) -> Optional[dict]:
    """Попробовать SSL/TLS — вернуть инфо о сертификате."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert    = tls.getpeercert()
                cipher  = tls.cipher()
                tls_ver = tls.version()
                subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
                issuer  = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
                cn      = subject.get("commonName", "")
                expiry  = cert.get("notAfter", "") if cert else ""
                org     = issuer.get("organizationName", "")
                bits    = cipher[2] if cipher else "?"
                c_name  = cipher[0] if cipher else "?"

                parts = []
                if tls_ver:
                    parts.append(tls_ver)
                if c_name:
                    parts.append(c_name)
                if bits:
                    parts.append(f"{bits}bit")
                if cn:
                    parts.append(f"CN={cn}")
                if org:
                    parts.append(f"issuer={org}")
                if expiry:
                    parts.append(f"exp={expiry}")

                return {
                    "banner":  " | ".join(parts),
                    "service": "HTTPS" if port in (443, 8443) else "SSL/TLS",
                    "version": tls_ver or "",
                    "cn": cn,
                    "expiry": expiry,
                }
    except Exception:
        return None


def try_http_probe_ssl(host: str, port: int, timeout: float) -> Optional[dict]:
    """HTTP HEAD через SSL."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = b""
                try:
                    while True:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if b"\r\n\r\n" in data or len(data) > 8192:
                            break
                except Exception:
                    pass
                if b"HTTP/" not in data:
                    return None
                text = data.decode("utf-8", errors="replace")
                server = ""
                m = re.search(r"(?:Server|X-Powered-By):\s*([^\r\n]+)", text, re.IGNORECASE)
                if m:
                    server = m.group(1).strip()
                return {
                    "service": "HTTPS",
                    "version": server,
                    "banner":  f"HTTP/{server}" if server else "HTTPS",
                }
    except Exception:
        return None


def raw_read(host: str, port: int, timeout: float) -> bytes:
    """Прочитать что пришло без запроса."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        time.sleep(0.3)
        data = b""
        try:
            while True:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
        except Exception:
            pass
        sock.close()
        return data
    except Exception:
        return b""


def extract_version_from_banner(banner: str, service: str) -> str:
    """Извлечь версию из произвольного баннера как fallback."""
    patterns = [
        re.compile(r"/(\d+\.\d+[\d._-]*)", re.IGNORECASE),
        re.compile(r"v(\d+\.\d+[\d._-]*)", re.IGNORECASE),
        re.compile(r"version[:\s]+(\d+\.\d+[\d._-]*)", re.IGNORECASE),
        re.compile(r"(\d+\.\d+\.\d+)", re.IGNORECASE),
    ]
    for pat in patterns:
        m = pat.search(banner)
        if m:
            return m.group(1)
    return ""


def scan_port(host: str, port: int, timeout: float = 1.5) -> Optional[dict]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connected = sock.connect_ex((host, port)) == 0
        sock.close()
        if not connected:
            return None

        # Детектирование сервиса и версии
        probe_timeout = min(timeout * 2, 4.0)
        info = detect_service_and_version(host, port, timeout=probe_timeout)

        # Если версия не найдена пробом — попробовать из баннера
        if not info["version"] and info["banner"]:
            info["version"] = extract_version_from_banner(info["banner"], info["service"])

        return {
            "port":    port,
            "state":   "open",
            "service": info["service"],
            "version": info["version"],
            "banner":  info["banner"],
            "ssl":     info["ssl"],
        }
    except Exception:
        return None
def scan_ports(host: str, ports: list, max_workers: int = 150, timeout: float = 1.5) -> list:
    total = len(ports)
    print(c(Colors.BLUE, f"\n  [*] Сканирование {total} портов на {host}..."))
    if total > 10000:
        print(c(Colors.DIM, f"      Полный диапазон — это займёт некоторое время. Потоков: {max_workers}"))

    open_ports = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            if result:
                open_ports.append(result)
                svc     = result["service"]
                ver     = result["version"]
                port_n  = result["port"]
                ssl_tag = c(Colors.CYAN, " [SSL]") if result.get("ssl") else ""
                svc_str = f"{svc} {ver}".strip() if ver else svc
                info    = f"{port_n}/{svc_str}"
                banner_short = result["banner"][:55] if result["banner"] else ""
                print(c(Colors.GREEN, f"  [+] {info:<45}") + ssl_tag + c(Colors.DIM, "  " + banner_short))

            # Прогресс-бар каждые 500 портов
            if done % 500 == 0 or done == total:
                pct  = done * 100 // total
                bars = int(pct / 5)
                bar  = "█" * bars + "░" * (20 - bars)
                print(c(Colors.DIM, f"      [{bar}] {pct:3d}%  {done}/{total}"), end="\r")

    print(" " * 80, end="\r")
    return sorted(open_ports, key=lambda x: x["port"])


# ─────────────────────────────────────────────
# ПРОВЕРКИ УЯЗВИМОСТЕЙ
# ─────────────────────────────────────────────
VULNERABILITY_CHECKS = {
    23:    [("Telnet открыт", "CRITICAL", "Telnet передаёт данные в открытом виде. Немедленно отключите, используйте SSH.")],
    21:    [("FTP открыт", "HIGH", "FTP не шифрует трафик. Используйте SFTP/FTPS.")],
    512:   [("rexec открыт", "CRITICAL", "Устаревший небезопасный сервис удалённого выполнения команд.")],
    513:   [("rlogin открыт", "CRITICAL", "Устаревший небезопасный сервис удалённого входа.")],
    514:   [("rsh открыт", "CRITICAL", "Небезопасная удалённая оболочка.")],
    2375:  [("Docker API без TLS", "CRITICAL", "Полный контроль над хостом без аутентификации.")],
    5900:  [("VNC открыт", "HIGH", "VNC часто имеет слабую аутентификацию.")],
    161:   [("SNMP открыт", "HIGH", "SNMP v1/v2c использует незащищённые community strings.")],
    6379:  [("Redis открыт", "CRITICAL", "Redis без аутентификации — полный доступ к данным.")],
    27017: [("MongoDB открыт", "CRITICAL", "MongoDB может быть доступна без аутентификации.")],
    9200:  [("Elasticsearch открыт", "CRITICAL", "Elasticsearch API может быть без аутентификации.")],
    11211: [("Memcached открыт", "HIGH", "Memcached без аутентификации, используется для DDoS.")],
    1080:  [("SOCKS Proxy открыт", "MEDIUM", "Открытый прокси для анонимизации атак.")],
    8888:  [("Jupyter Notebook открыт", "HIGH", "Jupyter без пароля = RCE на сервере.")],
    3389:  [("RDP открыт", "HIGH", "RDP подвержен BlueKeep/DejaBlue. Закройте от публичного доступа.")],
    445:   [("SMB открыт", "HIGH", "SMB подвержен EternalBlue/SMBGhost.")],
    139:   [("NetBIOS открыт", "MEDIUM", "NetBIOS раскрывает информацию о сети.")],
    111:   [("RPCbind открыт", "MEDIUM", "RPCbind может раскрывать NFS/NIS.")],
    2049:  [("NFS открыт", "HIGH", "NFS без ограничений позволяет монтировать ФС.")],
    7001:  [("WebLogic открыт", "CRITICAL", "WebLogic подвержен критическим RCE уязвимостям.")],
    6443:  [("Kubernetes API открыт", "HIGH", "API-сервер Kubernetes должен быть закрыт от публичного доступа.")],
}


def check_vulnerabilities(host: str, open_ports: list) -> list:
    print(c(Colors.BLUE, "\n  [*] Анализ уязвимостей..."))
    findings = []
    port_nums = {p["port"] for p in open_ports}

    for port_info in open_ports:
        port = port_info["port"]
        if port in VULNERABILITY_CHECKS:
            for (name, severity, desc) in VULNERABILITY_CHECKS[port]:
                findings.append({"port": port, "name": name, "severity": severity, "description": desc})
                color = SEVERITY_COLOR.get(severity, Colors.WHITE)
                print(f"  {c(color, f'[{severity}]'):<25} Порт {port}: {name}")

        banner_str = port_info.get("banner", "")
        version_str = port_info.get("version", "")
        if banner_str or version_str:
            for v in check_banner_vulns(port, banner_str, version_str):
                findings.append({"port": port, **v})
                sev = v["severity"]
                print(f"  {c(SEVERITY_COLOR.get(sev, Colors.WHITE), f'[{sev}]'):<25} Порт {port}: {v['name']}")

    # HTTP заголовки
    for hp in [p for p in open_ports if p["port"] in (80, 8080, 8000, 8008, 8081, 8090)]:
        for v in check_http(host, hp["port"]):
            findings.append({"port": hp["port"], **v})
            sev = v["severity"]
            print(f"  {c(SEVERITY_COLOR.get(sev, Colors.WHITE), f'[{sev}]'):<25} Порт {hp['port']}: {v['name']}")

    # SSL
    for sp in [p for p in open_ports if p["port"] in (443, 8443)]:
        for v in check_ssl(host, sp["port"]):
            findings.append({"port": sp["port"], **v})
            sev = v["severity"]
            print(f"  {c(SEVERITY_COLOR.get(sev, Colors.WHITE), f'[{sev}]'):<25} Порт {sp['port']}: {v['name']}")

    # Redis auth
    if 6379 in port_nums:
        for v in check_redis_auth(host):
            findings.append({"port": 6379, **v})
            sev = v["severity"]
            print(f"  {c(SEVERITY_COLOR.get(sev, Colors.WHITE), f'[{sev}]'):<25} Порт 6379: {v['name']}")

    # MongoDB auth
    if 27017 in port_nums:
        for v in check_mongodb_auth(host):
            findings.append({"port": 27017, **v})
            sev = v["severity"]
            print(f"  {c(SEVERITY_COLOR.get(sev, Colors.WHITE), f'[{sev}]'):<25} Порт 27017: {v['name']}")

    if not findings:
        print(c(Colors.GREEN, "  [+] Критичных уязвимостей не обнаружено."))
    return findings


def check_banner_vulns(port: int, banner: str, version: str = "") -> list:
    issues = []
    combined = (banner + " " + version).strip()
    bl = combined.lower()

    m = re.search(r"openssh[_\s]+([\d.]+)", bl)
    if m:
        ver = m.group(1)
        parts = ver.split(".")
        try:
            if int(parts[0]) < 8:
                issues.append({"name": f"Устаревший OpenSSH {ver}", "severity": "MEDIUM",
                                "description": f"OpenSSH {ver} содержит известные уязвимости. Обновите до 9.x."})
        except Exception:
            pass

    m = re.search(r"apache/([\d.]+)", bl)
    if m:
        ver = m.group(1)
        parts = ver.split(".")
        try:
            if int(parts[0]) < 2 or (int(parts[0]) == 2 and int(parts[1]) < 4):
                issues.append({"name": f"Устаревший Apache {ver}", "severity": "HIGH",
                                "description": "Устаревший Apache. Обновите до 2.4.x последней версии."})
        except Exception:
            pass

    m = re.search(r"nginx/([\d.]+)", bl)
    if m:
        ver = m.group(1)
        parts = ver.split(".")
        try:
            if int(parts[0]) < 1 or (int(parts[0]) == 1 and int(parts[1]) < 20):
                issues.append({"name": f"Устаревший nginx {ver}", "severity": "MEDIUM",
                                "description": f"nginx {ver} может содержать уязвимости. Обновите до стабильной ветки."})
        except Exception:
            pass

    return issues


def check_http(host: str, port: int) -> list:
    issues = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk or b"\r\n\r\n" in response:
                break
            response += chunk
        sock.close()
        headers_lower = response.decode("utf-8", errors="replace").split("\r\n\r\n")[0].lower()

        checks = {
            "x-frame-options": ("Отсутствует X-Frame-Options", "MEDIUM", "Уязвимость Clickjacking. Добавьте: X-Frame-Options: DENY"),
            "x-content-type-options": ("Отсутствует X-Content-Type-Options", "LOW", "Добавьте: X-Content-Type-Options: nosniff"),
            "strict-transport-security": ("Отсутствует HSTS", "MEDIUM", "Добавьте: Strict-Transport-Security: max-age=31536000"),
            "content-security-policy": ("Отсутствует CSP", "MEDIUM", "Content-Security-Policy не настроена. Защита от XSS ослаблена."),
        }
        for hdr, (name, severity, desc) in checks.items():
            if hdr not in headers_lower:
                issues.append({"name": name, "severity": severity, "description": desc})

        if re.search(r"server:\s*(apache|nginx|iis|php)/[\d.]+", headers_lower):
            issues.append({"name": "Раскрытие версии сервера", "severity": "LOW",
                           "description": "Скройте версию через ServerTokens Prod / server_tokens off."})
    except Exception:
        pass
    return issues


def check_ssl(host: str, port: int) -> list:
    issues = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version()
                cert = tls.getpeercert()
                cipher = tls.cipher()

                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    issues.append({"name": f"Устаревший протокол {version}", "severity": "HIGH",
                                   "description": f"{version} небезопасен. Используйте только TLS 1.2 и 1.3."})

                if cipher:
                    cn = cipher[0].upper()
                    if any(w in cn for w in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]):
                        issues.append({"name": f"Слабый шифр: {cn}", "severity": "HIGH",
                                       "description": "Используется слабый алгоритм шифрования."})

                if cert:
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        try:
                            expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.datetime.utcnow()).days
                            if days_left < 0:
                                issues.append({"name": "SSL сертификат истёк", "severity": "CRITICAL",
                                               "description": f"Истёк {abs(days_left)} дней назад."})
                            elif days_left < 30:
                                issues.append({"name": f"SSL истекает через {days_left} дней", "severity": "HIGH",
                                               "description": "Обновите SSL сертификат срочно."})
                            elif days_left < 90:
                                issues.append({"name": f"SSL истекает через {days_left} дней", "severity": "MEDIUM",
                                               "description": "Запланируйте обновление сертификата."})
                        except Exception:
                            pass
    except Exception:
        pass
    return issues


def check_redis_auth(host: str) -> list:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, 6379))
        sock.send(b"PING\r\n")
        resp = sock.recv(100).decode("utf-8", errors="replace")
        sock.close()
        if "+PONG" in resp:
            return [{"name": "Redis без аутентификации", "severity": "CRITICAL",
                     "description": "Redis отвечает без пароля. Настройте requirepass и ограничьте доступ по IP."}]
    except Exception:
        pass
    return []


def check_mongodb_auth(host: str) -> list:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, 27017))
        msg = b"\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x17\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
        sock.send(msg)
        resp = sock.recv(256)
        sock.close()
        if resp and len(resp) > 20:
            return [{"name": "MongoDB без аутентификации", "severity": "CRITICAL",
                     "description": "MongoDB доступна без аутентификации. Включите auth в mongod.conf."}]
    except Exception:
        pass
    return []


# ─────────────────────────────────────────────
# ПОИСК ЭКСПЛОЙТОВ ДЛЯ НАЙДЕННЫХ УЯЗВИМОСТЕЙ
# ─────────────────────────────────────────────
def find_exploits_for_findings(open_ports: list, findings: list, online: bool = True) -> dict:
    """
    Для каждого открытого порта найти релевантные эксплойты.
    Возвращает dict: port -> [exploit, ...]
    """
    print(c(Colors.BLUE, "\n  [*] Поиск эксплойтов..."))
    if online:
        print(c(Colors.DIM, "      (используются: локальная база + CIRCL CVE API — требуется интернет)"))
    else:
        print(c(Colors.DIM, "      (используется только локальная база, онлайн-поиск отключён)"))

    exploit_map = {}
    processed_keys = set()

    for port_info in open_ports:
        port = port_info["port"]
        service = port_info["service"]
        banner_str = port_info.get("banner", "")

        # Версия из port_info (уже определена probe-системой)
        version = port_info.get("version", "")
        if not version:
            vm = re.search(r"([\d]+\.[\d]+\.[\d]+)", banner_str)
            if vm:
                version = vm.group(1)

        # Собрать ключи поиска
        search_keys = set()
        search_keys.add(service.split("/")[0].lower())
        if port in PORT_TO_EXPLOIT_KEY:
            search_keys.update(PORT_TO_EXPLOIT_KEY[port])

        # Дедуплицировать между портами
        cache_key = frozenset(search_keys)
        if cache_key in processed_keys and not version:
            # Копируем из уже найденного порта с теми же ключами
            for prev_port, prev_exploits in exploit_map.items():
                if prev_exploits:
                    exploit_map[port] = prev_exploits
                    break
            continue
        processed_keys.add(cache_key)

        exploits = []
        for key in search_keys:
            result = search_exploits_for_service(key, version, port, online)
            for ex in result:
                # Дедупликация по CVE внутри порта
                if not any(e.get("cve") == ex.get("cve") and ex.get("cve") != "N/A"
                           for e in exploits):
                    exploits.append(ex)

        if exploits:
            exploit_map[port] = exploits[:6]  # Максимум 6 на порт
            print(c(Colors.YELLOW, f"  [!] Порт {port} ({service}): найдено {len(exploits[:6])} эксплойтов"))
        else:
            print(c(Colors.DIM, f"      Порт {port} ({service}): эксплойтов не найдено"))

    return exploit_map


# ─────────────────────────────────────────────
# ВЫВОД ОТЧЁТА
# ─────────────────────────────────────────────
def severity_order(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}.get(s, 9)


def print_report(host_info: dict, open_ports: list, findings: list,
                 exploit_map: dict, scan_time: float):
    print("\n" + c(Colors.CYAN, "═" * 68))
    print(c(Colors.BOLD, "  ИТОГОВЫЙ ОТЧЁТ БЕЗОПАСНОСТИ"))
    print(c(Colors.CYAN, "═" * 68))

    print(f"\n  {'Цель:':<22} {host_info['input']}")
    print(f"  {'IP:':<22} {host_info['ip']}")
    if host_info.get("hostname") and host_info["hostname"] != host_info["ip"]:
        print(f"  {'Hostname:':<22} {host_info['hostname']}")
    scope = c(Colors.YELLOW, "Приватная сеть") if host_info["is_private"] else c(Colors.RED, "Публичный интернет")
    print(f"  {'Область:':<22} {scope}")
    print(f"  {'Время сканирования:':<22} {scan_time:.1f} сек")

    # ── Открытые порты ──
    print(f"\n  {'Открытых портов:':<22} {c(Colors.GREEN if open_ports else Colors.DIM, str(len(open_ports)))}")
    if open_ports:
        print("\n" + c(Colors.CYAN, "  ─── ОТКРЫТЫЕ ПОРТЫ " + "─" * 48))
        print(f"  {'ПОРТ':<8} {'SSL':<5} {'СЕРВИС':<18} {'ВЕРСИЯ':<22} {'БАННЕР'}")
        print(c(Colors.DIM, "  " + "─" * 76))
        for p in open_ports:
            ssl_mark = c(Colors.CYAN, "YES") if p.get("ssl") else c(Colors.DIM, "-")
            ver  = (p.get("version","")[:20] + "…") if len(p.get("version","")) > 20 else p.get("version","")
            bs   = (p["banner"][:30] + "…") if len(p["banner"]) > 30 else p["banner"]
            port_colored = c(Colors.GREEN, str(p["port"]))
            print(f"  {port_colored:<16} {ssl_mark:<14} {p['service']:<18} {c(Colors.YELLOW, ver):<31} {c(Colors.DIM, bs)}")

    # ── Уязвимости ──
    findings_sorted = sorted(findings, key=lambda x: severity_order(x["severity"]))
    print("\n" + c(Colors.CYAN, "  ─── УЯЗВИМОСТИ " + "─" * 52))

    if not findings_sorted:
        print(c(Colors.GREEN, "  Уязвимостей не обнаружено!"))
    else:
        counts = {}
        for f in findings_sorted:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in counts:
                color = SEVERITY_COLOR.get(sev, Colors.WHITE)
                print(f"  {c(color, f'[{sev}]'):<25}: {counts[sev]} шт.")
        print()
        for f in findings_sorted:
            fsev  = f["severity"]
            fname = f["name"]
            fport = f["port"]
            fdesc = f["description"]
            color = SEVERITY_COLOR.get(fsev, Colors.WHITE)
            print(f"  {c(color, f'● [{fsev}]')}")
            print(f"    {c(Colors.BOLD, fname)} (порт {fport})")
            print(f"    {c(Colors.DIM, fdesc)}")
            print()

    # ── Эксплойты ──
    if exploit_map:
        print(c(Colors.CYAN, "  ─── НАЙДЕННЫЕ ЭКСПЛОЙТЫ " + "─" * 43))
        total_exploits = sum(len(v) for v in exploit_map.values())
        print(c(Colors.RED, f"  ⚠  Всего найдено: {total_exploits} эксплойтов\n"))

        for port, exploits in sorted(exploit_map.items()):
            svc = next((p["service"] for p in open_ports if p["port"] == port), "Unknown")
            print(c(Colors.BOLD, f"  ▶ Порт {port} / {svc}"))
            print(c(Colors.DIM, "  " + "─" * 64))

            for ex in exploits:
                cve   = ex.get("cve", "N/A")
                cvss  = ex.get("cvss", "?")
                title = ex.get("title", ex.get("description", "No title"))[:65]
                etype = ex.get("type", "")
                url   = ex.get("url", "")
                aff   = ex.get("affected", "")
                src   = ex.get("source", "")

                # Цвет по CVSS
                try:
                    cvss_f = float(cvss)
                    if cvss_f >= 9.0:
                        cvss_col = Colors.RED
                    elif cvss_f >= 7.0:
                        cvss_col = Colors.MAGENTA
                    elif cvss_f >= 4.0:
                        cvss_col = Colors.YELLOW
                    else:
                        cvss_col = Colors.BLUE
                except Exception:
                    cvss_col = Colors.DIM

                print(f"  {'CVE:':<8} {c(Colors.CYAN, cve):<30} CVSS: {c(cvss_col, str(cvss))}")
                print(f"  {'Тип:':<8} {etype}")
                print(f"  {'Эксплойт:':<8} {c(Colors.BOLD, title)}")
                if aff:
                    print(f"  {'Версии:':<8} {c(Colors.DIM, aff)}")
                print(f"  {'Ссылка:':<8} {c(Colors.BLUE, url)}")
                if src == "local-db":
                    edb_id = ex.get("edb_id", "")
                    if edb_id and edb_id != "N/A":
                        print(f"  {'EDB-ID:':<8} https://www.exploit-db.com/exploits/{edb_id}")
                print()
            print()

    # ── Итог ──
    print(c(Colors.CYAN, "═" * 68))
    total_ex = sum(len(v) for v in exploit_map.values())
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    risk = "🔴 КРИТИЧЕСКИЙ" if crit > 0 else ("🟠 ВЫСОКИЙ" if high > 0 else "🟡 СРЕДНИЙ" if findings else "🟢 НИЗКИЙ")
    print(f"\n  Общий уровень риска: {c(Colors.BOLD, risk)}")
    print(f"  Уязвимостей: {len(findings)}  |  Эксплойтов: {total_ex}  |  Критичных: {crit}\n")
    print(c(Colors.CYAN, "═" * 68) + "\n")


def save_report(filename: str, host_info: dict, open_ports: list,
                findings: list, exploit_map: dict, scan_time: float):
    report = {
        "scan_date": datetime.datetime.now().isoformat(),
        "target": host_info,
        "scan_duration_seconds": round(scan_time, 2),
        "open_ports": open_ports,
        "vulnerabilities": findings,
        "exploits": {str(k): v for k, v in exploit_map.items()},
        "summary": {
            "total_open_ports": len(open_ports),
            "total_findings": len(findings),
            "total_exploits": sum(len(v) for v in exploit_map.values()),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
        },
    }
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(c(Colors.GREEN, f"  [✓] Отчёт сохранён: {filename}"))


# ─────────────────────────────────────────────
# РАЗРЕШЕНИЕ ХОСТА
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# СКАНИРОВАНИЕ ПОДСЕТИ
# ─────────────────────────────────────────────
def ping_host(ip: str, timeout: float = 0.5) -> bool:
    """Быстрая проверка доступности хоста через TCP на популярных портах."""
    for port in [80, 22, 443, 445, 3389, 8080, 21, 23, 3306]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass
    # fallback: ICMP через raw socket (требует root) или просто считаем живым
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyaddr(ip)
        return True
    except Exception:
        pass
    return False


def sweep_subnet(network: str, max_workers: int = 200, timeout: float = 0.5) -> list:
    """
    Обнаружение живых хостов в подсети.
    Возвращает список IP-адресов, которые ответили хотя бы на один TCP-порт.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(c(Colors.RED, f"  [!] Некорректная подсеть: {e}"))
        sys.exit(1)

    hosts = [str(ip) for ip in net.hosts()]
    total = len(hosts)

    print(c(Colors.CYAN, f"\n  [*] Обнаружение хостов в {network} ({total} адресов)..."))

    alive = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, ip, timeout): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            done += 1
            ip = futures[future]
            if future.result():
                alive.append(ip)
                print(c(Colors.GREEN, f"  [+] {ip} — хост активен"))

            if done % 50 == 0 or done == total:
                pct  = done * 100 // total
                bars = int(pct / 5)
                bar  = "█" * bars + "░" * (20 - bars)
                print(c(Colors.DIM, f"      [{bar}] {pct:3d}%  {done}/{total}"), end="\r")

    print(" " * 80, end="\r")
    alive_sorted = sorted(alive, key=lambda ip: [int(x) for x in ip.split(".")])
    print(c(Colors.BOLD, f"\n  Найдено активных хостов: {c(Colors.GREEN, str(len(alive_sorted)))} из {total}\n"))
    return alive_sorted


def scan_subnet(network: str, ports: list, args) -> None:
    """Полный цикл сканирования всех хостов подсети."""
    alive_hosts = sweep_subnet(network, max_workers=200, timeout=args.timeout)

    if not alive_hosts:
        print(c(Colors.YELLOW, "  [!] Активных хостов не найдено."))
        return

    print(c(Colors.CYAN, "═" * 68))
    print(c(Colors.BOLD, f"  Начинаю сканирование {len(alive_hosts)} хостов..."))
    print(c(Colors.CYAN, "═" * 68))

    input(c(Colors.DIM, "\n  Нажмите Enter для начала (Ctrl+C — отмена)..."))

    subnet_results = []
    online = not args.offline

    for idx, ip in enumerate(alive_hosts, 1):
        print(c(Colors.CYAN, f"\n\n  ━━━ [{idx}/{len(alive_hosts)}] Сканирование {ip} {'━' * (40 - len(ip))}"))

        host_info = {"input": ip, "ip": ip, "hostname": None, "is_private": True}
        try:
            host_info["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        start_time = time.time()
        open_ports = scan_ports(ip, ports, max_workers=args.threads, timeout=args.timeout)

        findings    = []
        exploit_map = {}

        if not args.no_vulns and open_ports:
            findings = check_vulnerabilities(ip, open_ports)

        if not args.no_exploits and open_ports:
            exploit_map = find_exploits_for_findings(open_ports, findings, online=online)

        scan_time = time.time() - start_time
        print_report(host_info, open_ports, findings, exploit_map, scan_time)

        subnet_results.append({
            "host":       host_info,
            "open_ports": open_ports,
            "findings":   findings,
            "exploits":   exploit_map,
            "scan_time":  round(scan_time, 2),
        })

        # Сохранить отдельный JSON для каждого хоста если задан --output
        if args.output:
            base, ext = (args.output.rsplit(".", 1) + ["json"])[:2], "json"
            filename = f"{base[0]}_{ip.replace('.', '_')}.{ext}"
            save_report(filename, host_info, open_ports, findings, exploit_map, scan_time)

    # ── Итоговая сводка по подсети ──
    print(c(Colors.CYAN, "\n" + "═" * 68))
    print(c(Colors.BOLD, "  СВОДКА ПО ПОДСЕТИ: " + network))
    print(c(Colors.CYAN, "═" * 68))
    print(f"  {'Хостов проверено:':<28} {len(alive_hosts)}")

    total_ports   = sum(len(r["open_ports"]) for r in subnet_results)
    total_vulns   = sum(len(r["findings"])   for r in subnet_results)
    total_exploits= sum(sum(len(v) for v in r["exploits"].values()) for r in subnet_results)
    total_crits   = sum(sum(1 for f in r["findings"] if f["severity"] == "CRITICAL") for r in subnet_results)

    print(f"  {'Открытых портов (всего):':<28} {total_ports}")
    print(f"  {'Уязвимостей (всего):':<28} {total_vulns}")
    print(f"  {'Критичных:':<28} {c(Colors.RED, str(total_crits)) if total_crits else c(Colors.GREEN, '0')}")
    print(f"  {'Эксплойтов (всего):':<28} {total_exploits}")
    print()

    for r in subnet_results:
        ip   = r["host"]["ip"]
        hn   = r["host"].get("hostname") or ""
        op   = len(r["open_ports"])
        cr   = sum(1 for f in r["findings"] if f["severity"] == "CRITICAL")
        hi   = sum(1 for f in r["findings"] if f["severity"] == "HIGH")
        ex   = sum(len(v) for v in r["exploits"].values())
        risk_icon = "🔴" if cr else ("🟠" if hi else ("🟡" if r["findings"] else "🟢"))
        host_str  = f"{ip}" + (f" ({hn})" if hn else "")
        print(f"  {risk_icon}  {host_str:<35} портов: {op:<4} уязв: {len(r['findings']):<4} эксплойтов: {ex}")

    print(c(Colors.CYAN, "\n" + "═" * 68 + "\n"))

    # Сохранить общий JSON-отчёт по подсети
    if args.output:
        subnet_report = {
            "scan_date": datetime.datetime.now().isoformat(),
            "subnet":    network,
            "hosts":     subnet_results,
            "summary": {
                "total_hosts":    len(alive_hosts),
                "total_ports":    total_ports,
                "total_findings": total_vulns,
                "total_exploits": total_exploits,
                "critical":       total_crits,
            },
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(subnet_report, fh, ensure_ascii=False, indent=2,
                      default=lambda o: str(o))
        print(c(Colors.GREEN, f"  [✓] Общий отчёт по подсети сохранён: {args.output}"))


def resolve_host(host: str) -> dict:
    info = {"input": host, "ip": None, "hostname": None, "is_private": False}
    try:
        ip = socket.gethostbyname(host)
        info["ip"] = ip
        try:
            info["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        try:
            info["is_private"] = ipaddress.ip_address(ip).is_private
        except Exception:
            pass
    except socket.gaierror as e:
        print(c(Colors.RED, f"  [!] Не удалось разрешить хост {host}: {e}"))
        sys.exit(1)
    return info


def parse_ports(ports_str: str) -> list:
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Сканер безопасности серверов v2.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  %(prog)s --target 192.168.1.1                         # полный скан одного хоста
  %(prog)s --target 192.168.1.1 --top-ports             # только топ-100 портов (быстро)
  %(prog)s --target example.com --ports 1-1024          # конкретный диапазон
  %(prog)s --target 10.0.0.1 --output report.json       # сохранить отчёт
  %(prog)s --target 10.0.0.1 --no-exploits              # без поиска эксплойтов
  %(prog)s --target 10.0.0.1 --offline                  # только локальная база CVE
  %(prog)s --subnet 192.168.1.0/24                      # скан всей подсети
  %(prog)s --subnet 192.168.1.0/24 --top-ports          # подсеть + топ-100 портов
  %(prog)s --subnet 10.0.0.0/24 --output subnet.json    # подсеть с отчётом
        """
    )
    parser.add_argument("--target",      default=None,          help="IP-адрес или hostname цели")
    parser.add_argument("--subnet",      default=None,          help="Подсеть в CIDR нотации: 192.168.1.0/24")
    parser.add_argument("--ports",       default=None,          help="Порты: 80,443,1000-2000")
    parser.add_argument("--top-ports",   action="store_true",   help="Только топ-100 популярных портов (быстро)")
    parser.add_argument("--threads",     type=int, default=150, help="Количество потоков (150)")
    parser.add_argument("--timeout",     type=float, default=1.5, help="Таймаут (сек)")
    parser.add_argument("--output",      default=None,          help="Сохранить отчёт в JSON")
    parser.add_argument("--no-vulns",    action="store_true",   help="Только порты, без анализа")
    parser.add_argument("--no-exploits", action="store_true",   help="Без поиска эксплойтов")
    parser.add_argument("--offline",     action="store_true",   help="Только локальная база CVE")

    args = parser.parse_args()

    if not args.target and not args.subnet:
        parser.error("Необходимо указать --target или --subnet")

    if args.ports:
        ports = parse_ports(args.ports)
    elif args.top_ports:
        ports = TOP_100_PORTS
    else:
        # По умолчанию — полный диапазон 1-65535
        ports = list(range(1, 65536))

    # ── Режим сканирования подсети ──
    if args.subnet:
        print(c(Colors.YELLOW, f"\n  ⚠  Сканирование подсети {args.subnet}"))
        print(c(Colors.RED,    "     Сканируйте ТОЛЬКО свои сети или при наличии разрешения!"))
        scan_subnet(args.subnet, ports, args)
        return

    # ── Режим одиночного хоста ──
    host_info = resolve_host(args.target)
    print(c(Colors.WHITE, "\n  Цель: ") + c(Colors.BOLD, host_info["input"]) +
          c(Colors.DIM, f" → {host_info['ip']}"))

    if host_info["is_private"]:
        print(c(Colors.YELLOW, "  ⚠  Приватная сеть — убедитесь в наличии разрешения!"))
    else:
        print(c(Colors.RED, "  ⚠  Публичный хост — сканируйте ТОЛЬКО свои серверы!"))

    input(c(Colors.DIM, "\n  Нажмите Enter для начала (Ctrl+C — отмена)..."))

    start_time = time.time()

    open_ports = scan_ports(host_info["ip"], ports, max_workers=args.threads, timeout=args.timeout)

    findings = []
    exploit_map = {}

    if not args.no_vulns and open_ports:
        findings = check_vulnerabilities(host_info["ip"], open_ports)

    if not args.no_exploits and open_ports:
        online = not args.offline
        exploit_map = find_exploits_for_findings(open_ports, findings, online=online)

    scan_time = time.time() - start_time

    print_report(host_info, open_ports, findings, exploit_map, scan_time)

    if args.output:
        save_report(args.output, host_info, open_ports, findings, exploit_map, scan_time)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c(Colors.YELLOW, "\n\n  [!] Прервано пользователем."))
        sys.exit(0)
