# 🔍 Server Security Scanner v2.1

> Инструмент для аудита безопасности серверов: сканирование портов, определение сервисов и версий, поиск уязвимостей и эксплойтов.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Dependencies](https://img.shields.io/badge/Dependencies-none-brightgreen)

---

## ✨ Возможности

| Функция | Описание |
|---|---|
| 🔎 **Сканирование портов** | Полный диапазон 1–65535 по умолчанию, параллельно (до 500+ потоков) |
| 🧠 **Определение сервиса** | Protocol probing — 14 протоколов без nmap |
| 🏷️ **Определение версии** | SSH, FTP, HTTP, Redis, MySQL, Nginx, Apache и др. |
| 🔐 **SSL/TLS анализ** | Версия, шифр, CN, дата истечения, слабые протоколы |
| ⚠️ **Анализ уязвимостей** | 20+ статических проверок по сервисам |
| 💣 **Поиск эксплойтов** | Локальная база CVE + онлайн CIRCL CVE API |
| 📄 **Отчёт в JSON** | Полный машиночитаемый отчёт с CVE, CVSS, ссылками |

---

## 🚀 Быстрый старт

```bash
# Клонировать репозиторий
git clone https://github.com/YOUR_USERNAME/security-scanner.git
cd security-scanner

# Запустить (зависимостей нет — только стандартная библиотека Python)
python3 security_scanner.py --target 192.168.1.1
```

---

## 📖 Использование

```
python3 security_scanner.py --target TARGET [опции]
```

### Аргументы

| Аргумент | По умолчанию | Описание |
|---|---|---|
| `--target` | обязательный | IP-адрес или hostname |
| `--ports` | — | Конкретные порты: `80,443` или `1-1024` |
| `--top-ports` | — | Только топ-100 популярных портов (быстро) |
| `--threads` | `150` | Количество параллельных потоков |
| `--timeout` | `1.5` | Таймаут подключения (секунды) |
| `--output` | — | Сохранить отчёт в JSON-файл |
| `--no-vulns` | — | Только сканирование портов |
| `--no-exploits` | — | Без поиска эксплойтов |
| `--offline` | — | Только локальная база CVE (без интернета) |

### Примеры

```bash
# Полный скан всех 65535 портов (по умолчанию)
python3 security_scanner.py --target 10.0.0.1

# Быстрый скан топ-100 портов
python3 security_scanner.py --target 10.0.0.1 --top-ports

# Конкретный диапазон портов
python3 security_scanner.py --target example.com --ports 1-1024

# Сохранить полный отчёт в JSON
python3 security_scanner.py --target 10.0.0.1 --output report.json

# Максимальная скорость
python3 security_scanner.py --target 10.0.0.1 --threads 500 --timeout 1.0

# Без интернета (только локальная база)
python3 security_scanner.py --target 10.0.0.1 --offline
```

---

## 🧠 Как работает определение сервисов

Скрипт использует **Protocol Probing** — активное зондирование каждого открытого порта специфичными запросами для каждого протокола:

```
Порт открыт
    │
    ├─→ SSL/TLS handshake → сертификат, шифр, версия TLS
    │
    ├─→ HTTP HEAD / → Server: nginx/1.24.0
    │
    ├─→ SSH читает баннер → SSH-2.0-OpenSSH_9.3p1
    │
    ├─→ Redis PING + INFO server → redis_version:7.2.1
    │
    ├─→ MySQL handshake → 8.0.35-MySQL
    │
    ├─→ Memcached version → VERSION 1.6.21
    │
    └─→ Raw read → любой текстовый баннер
```

Поддерживаемые протоколы: **HTTP, HTTPS, SSH, FTP, SMTP, POP3, IMAP, Redis, MySQL, MongoDB, Memcached, RDP, VNC, SMB, PostgreSQL, Elasticsearch, Docker API**

---

## 💣 База эксплойтов

Встроенная база содержит наиболее критичные CVE с прямыми ссылками на Exploit-DB:

| Сервис | CVE | CVSS | Тип атаки |
|---|---|---|---|
| SMB | CVE-2017-0144 | 9.3 | EternalBlue — Wormable RCE |
| SMB | CVE-2020-0796 | 10.0 | SMBGhost — Pre-Auth RCE |
| RDP | CVE-2019-0708 | 9.8 | BlueKeep — Pre-Auth RCE |
| SSH | CVE-2024-6387 | 8.1 | regreSSHion — Pre-Auth RCE |
| Redis | CVE-2022-0543 | 10.0 | Lua Sandbox Escape RCE |
| Apache | CVE-2021-41773 | 7.5 | Path Traversal / RCE |
| WebLogic | CVE-2020-14882 | 9.8 | Unauth Console RCE |
| Docker API | — | 10.0 | Unauth Host Takeover |
| Elasticsearch | CVE-2015-1427 | 10.0 | Groovy Sandbox Escape |
| MySQL | CVE-2012-2122 | 7.5 | Auth Bypass |
| ... | ... | ... | ... |

Дополнительно — онлайн-поиск через **CIRCL CVE Search API** (бесплатно, без ключа).

---

## 📊 Пример вывода

```
  [+] 22/SSH 2.0-OpenSSH_8.9p1           SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  [+] 80/HTTP nginx/1.24.0               HTTP/200 Server: nginx/1.24.0
  [+] 443/HTTPS TLSv1.3                  TLSv1.3 | TLS_AES_256_GCM_SHA384 | CN=example.com
  [+] 3306/MySQL 8.0.35-MySQL            8.0.35-MySQL Community Server

  [CRITICAL]   Порт 6379: Redis без аутентификации
  [HIGH]       Порт 445:  SMB открыт
  [HIGH]       Порт 3389: RDP открыт

  ▶ Порт 445 / SMB
  CVE: CVE-2017-0144          CVSS: 9.3
  Тип: Remote Code Execution (Wormable)
  Эксплойт: EternalBlue — MS17-010 SMB RCE
  Версии: Windows XP–Server 2008 R2 без патча MS17-010
  Ссылка: https://www.exploit-db.com/exploits/42315
```

---

## 📋 Формат JSON-отчёта

```json
{
  "scan_date": "2024-01-15T14:30:00",
  "target": { "ip": "10.0.0.1", "hostname": "server.local" },
  "open_ports": [
    {
      "port": 22,
      "service": "SSH",
      "version": "2.0-OpenSSH_8.9p1",
      "ssl": false,
      "banner": "SSH-2.0-OpenSSH_8.9p1"
    }
  ],
  "vulnerabilities": [
    {
      "port": 445,
      "name": "SMB открыт",
      "severity": "HIGH",
      "description": "..."
    }
  ],
  "exploits": {
    "445": [
      {
        "cve": "CVE-2017-0144",
        "cvss": 9.3,
        "title": "EternalBlue",
        "url": "https://www.exploit-db.com/exploits/42315"
      }
    ]
  },
  "summary": {
    "total_open_ports": 5,
    "total_findings": 3,
    "total_exploits": 7
  }
}
```

---

## ⚙️ Требования

- Python **3.8+**
- Зависимости: **отсутствуют** (только стандартная библиотека)
- Для онлайн-поиска CVE: доступ к интернету (CIRCL CVE API)

---

## ⚠️ Правовая оговорка

> Данный инструмент предназначен **исключительно** для тестирования безопасности **собственной** инфраструктуры или систем, на проверку которых получено **явное письменное разрешение**.
>
> Несанкционированное сканирование чужих систем является **уголовно наказуемым** во многих странах.
>
> Автор не несёт ответственности за любое незаконное использование данного инструмента.

---

## 📄 Лицензия

MIT License — свободное использование, изменение и распространение с сохранением авторства.
