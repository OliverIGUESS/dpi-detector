import asyncio
import ssl
import sys
import socket
import warnings
import time
import errno
import re
import math
import config
import os
import traceback
from typing import Tuple, Optional, List
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

try:
    import httpx
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    import aiodns
except ImportError as e:
    print(f"Ошибка: {e}")
    print("Установите зависимости: python -m pip install -r requirements.txt")
    sys.exit(1)

console = Console(record=True)

# =================== Конфиг
USE_IPV4_ONLY = config.USE_IPV4_ONLY
MAX_CONCURRENT = config.MAX_CONCURRENT
TIMEOUT = config.TIMEOUT
TIMEOUT_TCP_16_20 = config.TIMEOUT_TCP_16_20
DOMAIN_CHECK_RETRIES = config.DOMAIN_CHECK_RETRIES
TCP_16_20_CHECK_RETRIES = config.TCP_16_20_CHECK_RETRIES
TCP_BLOCK_MIN_KB = config.TCP_BLOCK_MIN_KB
TCP_BLOCK_MAX_KB = config.TCP_BLOCK_MAX_KB
SHOW_DATA_SIZE = config.SHOW_DATA_SIZE
BODY_INSPECT_LIMIT = config.BODY_INSPECT_LIMIT
DATA_READ_THRESHOLD = config.DATA_READ_THRESHOLD
USER_AGENT = config.USER_AGENT
BLOCK_MARKERS = config.BLOCK_MARKERS
BODY_BLOCK_MARKERS = config.BODY_BLOCK_MARKERS
WSAECONNRESET = config.WSAECONNRESET
WSAECONNREFUSED = config.WSAECONNREFUSED
WSAETIMEDOUT = config.WSAETIMEDOUT
WSAENETUNREACH = config.WSAENETUNREACH
WSAEHOSTUNREACH = config.WSAEHOSTUNREACH
WSAECONNABORTED = config.WSAECONNABORTED
WSAENETDOWN = config.WSAENETDOWN
WSAEACCES = config.WSAEACCES
DPI_VARIANCE_THRESHOLD = config.DPI_VARIANCE_THRESHOLD

# DNS проверка
DNS_CHECK_ENABLED = config.DNS_CHECK_ENABLED
DNS_CHECK_TIMEOUT = config.DNS_CHECK_TIMEOUT
DNS_CHECK_DOMAINS = config.DNS_CHECK_DOMAINS
DNS_UDP_SERVERS = config.DNS_UDP_SERVERS
DNS_DOH_SERVERS = config.DNS_DOH_SERVERS

# DEBUG MODE - включить детальное логирование
DEBUG_MODE = False
DEBUG_DOMAINS = []  # Пустой список = все домены, или ["amnezia.org", "kino.pub"]


def debug_log(message: str, level: str = "INFO"):
    """Логирование debug сообщений."""
    if not DEBUG_MODE:
        return

    colors = {
        "INFO": "cyan",
        "ERROR": "red",
        "SUCCESS": "green",
        "WARNING": "yellow",
        "DEBUG": "magenta"
    }
    color = colors.get(level, "white")
    console.print(f"[{color}][DEBUG {level}][/{color}] {message}")


def get_exe_dir() -> str:
    """Возвращает директорию рядом с .exe (или со скриптом при запуске напрямую)."""
    if getattr(sys, 'frozen', False):
        # Запущено как .exe — берём папку где лежит exe
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_resource_path(relative_path):
    """Ищет файл: сначала рядом с exe/скриптом, потом в бандле PyInstaller."""
    # 1. Файл рядом с exe или скриптом (пользовательский, приоритет)
    external = os.path.join(get_exe_dir(), relative_path)
    if os.path.exists(external):
        return external

    # 2. Файл внутри PyInstaller бандла (встроенный по умолчанию)
    try:
        bundled = os.path.join(sys._MEIPASS, relative_path)
        if os.path.exists(bundled):
            return bundled
    except AttributeError:
        pass

    # 3. Fallback — вернуть путь рядом с exe (чтобы сообщение об ошибке было понятным)
    return external


def load_domains(filepath="domains.txt"):
    """Загружает домены из файла с проверкой наличия."""
    domains = []
    full_path = get_resource_path(filepath)

    if not os.path.exists(full_path):
        console.print(f"[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
        console.print(f"[red]Путь: {full_path}[/red]")
        console.print("[yellow]Положите domains.txt рядом со скриптом.[/yellow]")
        sys.exit(1) # Останавливаем скрипт

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
    except Exception as e:
        console.print(f"[bold red]Ошибка чтения файла {filepath}: {e}[/bold red]")
        sys.exit(1)

    return domains


def load_tcp_targets(filepath="tcp_16_20_targets.json"):
    """Загружает TCP цели из JSON."""
    import json
    full_path = get_resource_path(filepath)

    if not os.path.exists(full_path):
            console.print(f"[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
            console.print(f"[red]Путь: {full_path}[/red]")
            sys.exit(1)

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]ОШИБКА: Некорректный JSON в {filepath}![/bold red]")
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except FileNotFoundError:
        console.print(f"[bold red]Ошибка чтения {filepath}: {e}[/bold red]")
        sys.exit(1)


DOMAINS = load_domains()
TCP_16_20_ITEMS = load_tcp_targets()

if USE_IPV4_ONLY:
    import socket as _socket
    _original_getaddrinfo = _socket.getaddrinfo

    def _getaddrinfo_ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
        """Возвращает только IPv4 адреса."""
        return _original_getaddrinfo(host, port, _socket.AF_INET, type, proto, flags)

    _socket.getaddrinfo = _getaddrinfo_ipv4_only


def _find_cause_of_type(exc: Exception, target_type: type, max_depth: int = 10):
    """Ищет в цепочке ошибок первое исключение заданного типа."""
    current = exc
    for _ in range(max_depth):
        if isinstance(current, target_type):
            return current
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def _get_errno_from_chain(exc: Exception, max_depth: int = 10) -> Optional[int]:
    """Извлекает errno из цепочки ошибок."""
    current = exc
    for _ in range(max_depth):
        if isinstance(current, OSError) and current.errno is not None:
            return current.errno
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def _collect_error_text(exc: Exception, max_depth: int = 10) -> str:
    """Собирает текст из всей цепочки исключений."""
    parts = []
    current = exc
    for _ in range(max_depth):
        parts.append(str(current).lower())
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return " | ".join(parts)


def debug_exception(exc: Exception, domain: str, context: str = ""):
    """Детальный вывод информации об исключении."""
    if not DEBUG_MODE:
        return

    if DEBUG_DOMAINS and domain not in DEBUG_DOMAINS:
        return

    console.print(f"\n{'='*80}", style="red")
    console.print(f"[bold red]EXCEPTION DEBUG: {domain}[/bold red]")
    if context:
        console.print(f"[yellow]Context: {context}[/yellow]")
    console.print(f"{'='*80}", style="red")

    # Основная информация
    console.print(f"\n[bold cyan]Exception Type:[/bold cyan] {type(exc).__name__}")
    console.print(f"[bold cyan]Exception Message:[/bold cyan] {str(exc)}")
    console.print(f"[bold cyan]Exception Repr:[/bold cyan] {repr(exc)}")

    # Атрибуты исключения
    console.print(f"\n[bold cyan]Exception Attributes:[/bold cyan]")
    important_attrs = ['errno', 'args', 'strerror', 'filename', 'verify_code', 'verify_message']
    for attr in important_attrs:
        if hasattr(exc, attr):
            val = getattr(exc, attr)
            console.print(f"  [green]{attr}:[/green] {val}")

    # Цепочка исключений
    console.print(f"\n[bold cyan]Exception Chain:[/bold cyan]")
    current = exc
    depth = 0
    while current and depth < 10:
        indent = "  " * depth
        console.print(f"{indent}[{depth}] [yellow]{type(current).__name__}:[/yellow] {current}")

        if isinstance(current, OSError) and hasattr(current, 'errno'):
            console.print(f"{indent}    errno: {current.errno}")
        if hasattr(current, 'args'):
            console.print(f"{indent}    args: {current.args}")

        nxt = current.__cause__ or current.__context__
        if nxt:
            console.print(f"{indent}    ↓ {'__cause__' if current.__cause__ else '__context__'}")
        current = nxt
        depth += 1

    # Полный текст цепочки
    full_text = _collect_error_text(exc)
    console.print(f"\n[bold cyan]Full Error Text:[/bold cyan]")
    console.print(f"  {full_text}")


# =================== DNS ПРОВЕРКА ===================

async def _probe_dns_server(nameserver: str, domains: list) -> dict:
    """
    Пробует резолвить список доменов через UDP DNS-сервер.
    Возвращает {'ok': int, 'timeout': int, 'error': int, 'results': {domain: ips|str}}.
    """
    ok = timeout = error = 0
    results = {}
    for domain in domains:
        resolver = aiodns.DNSResolver(nameservers=[nameserver], timeout=DNS_CHECK_TIMEOUT)
        try:
            r = await resolver.query(domain, 'A')
            ips = [x.host for x in r]
            results[domain] = ips if ips else "EMPTY"
            ok += 1
        except aiodns.error.DNSError as e:
            code = e.args[0] if e.args else None
            msg = str(e).lower()
            if code in (11, 12) or "timeout" in msg or "refused" in msg:
                results[domain] = "TIMEOUT"
                timeout += 1
            elif code == 4 or "not found" in msg:
                results[domain] = "NXDOMAIN"
                ok += 1  # NXDOMAIN — сервер отвечает
            else:
                results[domain] = "ERROR"
                error += 1
        except asyncio.TimeoutError:
            results[domain] = "TIMEOUT"
            timeout += 1
        except Exception:
            results[domain] = "ERROR"
            error += 1
    return {"ok": ok, "timeout": timeout, "error": error, "results": results}


async def _probe_doh_server(doh_url: str, domains: list) -> dict:
    """
    Пробует резолвить список доменов через DoH-сервер.
    Возвращает {'ok': int, 'timeout': int, 'blocked': int, 'results': {domain: ips|str}}.
    """
    ok = timeout = blocked = 0
    results = {}
    headers = {"Accept": "application/dns-json", "User-Agent": USER_AGENT}
    for domain in domains:
        try:
            async with httpx.AsyncClient(timeout=DNS_CHECK_TIMEOUT, verify=False, headers=headers) as client:
                resp = await client.get(doh_url, params={"name": domain, "type": "A"})
                if resp.status_code != 200:
                    results[domain] = "BLOCKED"
                    blocked += 1
                    continue
                data = resp.json()
                if data.get("Status") == 3:
                    results[domain] = "NXDOMAIN"
                    ok += 1
                    continue
                ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                results[domain] = ips if ips else "EMPTY"
                ok += 1
        except httpx.TimeoutException:
            results[domain] = "TIMEOUT"
            timeout += 1
        except httpx.ConnectError:
            results[domain] = "BLOCKED"
            blocked += 1
        except Exception:
            results[domain] = "ERROR"
            blocked += 1
    return {"ok": ok, "timeout": timeout, "blocked": blocked, "results": results}


def _is_server_unavailable(probe: dict, total: int, threshold: float = 0.6) -> bool:
    """True если сервер недоступен — слишком много таймаутов/ошибок."""
    bad = probe.get("timeout", 0) + probe.get("error", 0) + probe.get("blocked", 0)
    return bad / max(total, 1) >= threshold


async def check_dns_integrity():
    """
    Проверяет целостность DNS.
    Последовательно опрашивает все серверы из DNS_UDP_SERVERS и DNS_DOH_SERVERS.
    Ищет первый рабочий UDP и первый рабочий DoH — сравнивает их ответы.
    Возвращает set IP-адресов заглушек.
    """
    if not DNS_CHECK_ENABLED:
        return set()

    total = len(DNS_CHECK_DOMAINS)

    console.print("\n[bold]Проверка DNS целостности[/bold]")
    console.print("[dim]Проверяем, перехватывает ли провайдер DNS запросы...[/dim]\n")

    # ── Шаг 1: найти рабочий UDP-сервер ──────────────────────────────────────
    udp_probe = None
    udp_label = None
    for udp_ip, udp_name in DNS_UDP_SERVERS:
        probe = await _probe_dns_server(udp_ip, DNS_CHECK_DOMAINS)
        bad = probe["timeout"] + probe["error"]
        good = total - bad
        if good >= max(1, total // 2):          # хотя бы половина доменов резолвится
            udp_probe = probe
            udp_label = f"DNS {udp_ip}:53 ({udp_name})"
            break
        else:
            console.print(
                f"[yellow][!] DNS {udp_ip} ({udp_name}): {probe['timeout']}/{total} таймаут, "
                f"{probe['error']}/{total} ошибок — пробую следующий...[/yellow]"
            )

    if udp_probe is None:
        console.print("[red]× Все UDP DNS-серверы недоступны — UDP/53 заблокирован у провайдера[/red]\n")
        udp_probe = {"results": {d: "UNAVAIL" for d in DNS_CHECK_DOMAINS}}
        udp_label = "UDP DNS (недоступен)"

    # ── Шаг 2: найти рабочий DoH-сервер ──────────────────────────────────────
    doh_probe = None
    doh_label = None
    for doh_url, doh_name in DNS_DOH_SERVERS:
        probe = await _probe_doh_server(doh_url, DNS_CHECK_DOMAINS)
        bad = probe["timeout"] + probe.get("blocked", 0)
        good = total - bad
        if good >= max(1, total // 2):
            doh_probe = probe
            doh_label = f"DoH ({doh_name})"
            break
        else:
            console.print(
                f"[yellow][!] DoH {doh_name}: {probe['timeout']}/{total} таймаут, "
                f"{probe.get('blocked',0)}/{total} блок — пробую следующий...[/yellow]"
            )

    if doh_probe is None:
        console.print("[red]× Все DoH-серверы недоступны — DoH заблокирован у провайдера[/red]\n")
        doh_probe = {"results": {d: "UNAVAIL" for d in DNS_CHECK_DOMAINS}}
        doh_label = "DoH (недоступен)"

    # ── Шаг 3: анализ результатов ─────────────────────────────────────────────
    results = []
    dns_intercept_count = 0
    doh_blocked_count   = 0
    timeout_count       = 0
    failed_domains      = []
    udp_ips_collection  = {}   # domain -> [ips] из UDP (для stub-детектора)

    for domain in DNS_CHECK_DOMAINS:
        udp_res = udp_probe["results"].get(domain)
        doh_res = doh_probe["results"].get(domain)

        udp_ips = udp_res if isinstance(udp_res, list) else None
        doh_ips = doh_res if isinstance(doh_res, list) else None

        if udp_ips:
            udp_ips_collection[domain] = udp_ips

        udp_str = ", ".join(udp_ips[:2]) if udp_ips else str(udp_res or "—")
        doh_str = ", ".join(doh_ips[:2]) if doh_ips else str(doh_res or "—")

        if udp_res == "TIMEOUT":
            timeout_count += 1
        if doh_res == "BLOCKED":
            doh_blocked_count += 1

        # Статус строки
        if doh_ips and udp_ips:
            if set(doh_ips) == set(udp_ips):
                status = "[green]√ DNS OK[/green]"
            else:
                status = "[red]× DNS ПОДМЕНА[/red]"
                dns_intercept_count += 1
        elif doh_ips and not udp_ips:
            if udp_res in ("TIMEOUT", "NXDOMAIN"):
                status = "[red]× DNS ПЕРЕХВАТ[/red]"
                dns_intercept_count += 1
            else:
                status = "[yellow]× UDP недоступен[/yellow]"
                failed_domains.append(domain)
        elif udp_ips and not doh_ips:
            if doh_res == "BLOCKED":
                status = "[yellow]× DoH заблокирован[/yellow]"
            else:
                status = "[yellow]× DoH недоступен[/yellow]"
        else:
            status = "[red]× Оба недоступны[/red]"
            failed_domains.append(domain)

        results.append([domain, doh_str, udp_str, status])

    # ── Шаг 4: заглушки ───────────────────────────────────────────────────────
    stub_ips = set()
    ip_count: dict = {}
    for ips in udp_ips_collection.values():
        for ip in ips:
            ip_count[ip] = ip_count.get(ip, 0) + 1
    for ip, cnt in ip_count.items():
        if cnt >= 2:
            stub_ips.add(ip)

    # ── Шаг 5: таблица ────────────────────────────────────────────────────────
    dns_table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    dns_table.add_column("Домен", style="cyan")
    dns_table.add_column(doh_label, style="dim")
    dns_table.add_column(udp_label, style="dim")
    dns_table.add_column("Статус")

    for r in results:
        dns_table.add_row(*r)

    console.print(dns_table)
    console.print()

    # ── Шаг 6: диагностика ────────────────────────────────────────────────────
    if dns_intercept_count > 0:
        console.print("[bold red][!] Ваш интернет-провайдер перехватывает DNS-запросы[/bold red]")
        console.print("Провайдер подменяет ответы UDP DNS на заглушки или ложные NXDOMAIN\n")
        console.print(
            "[bold yellow]ВНИМАНИЕ: Это независимая проверка и она не использует ваши настроенные DNS![/bold yellow]\n"
            "[bold yellow]Рекомендация:[/bold yellow] Настройте DoH на устройстве,роутере и VPN.\n"
            "[bold green]Если DoH уже настроен — игнорируйте эту проверку.[bold green]\n"
        )

    if doh_blocked_count > 0:
        console.print(
            f"[bold red][!] DoH заблокирован[/bold red] — "
            f"провайдер блокирует зашифрованный DNS на порту 443\n"
            f"[yellow]Попробуйте другой DoH-сервер или туннель через VPN[/yellow]\n"
        )

    if timeout_count > 0 and dns_intercept_count == 0:
        console.print(
            f"[yellow][!] Часть запросов завершилась таймаутом ({timeout_count}/{total * 2})[/yellow]\n"
            f"[dim]Провайдер может фильтровать UDP/53 или DoH трафик[/dim]\n"
        )

    if len(failed_domains) == total:
        console.print("[bold red]× Не удалось разрешить ни один домен[/bold red]\n")
    elif len(failed_domains) >= 2:
        console.print(
            f"[yellow][!] Не удалось разрешить: {', '.join(failed_domains)}[/yellow]\n"
        )

    return stub_ips, dns_intercept_count


def _clean_detail(detail: str) -> str:
    """Очистка деталей от лишнего текста."""
    if not detail or detail in ("OK", "Error"):
        return ""
    detail = detail.replace("The operation did not complete", "TLS Aborted")
    detail = re.sub(r"\s*\([^)]*\)?\s*", " ", detail)
    detail = re.sub(r"\s*\(_*\s*$", "", detail)
    detail = re.sub(r"\s+", " ", detail).strip()
    detail = detail.replace("Err None: ", "").replace("Conn failed: ", "")
    if re.match(r"^HTTP [23]\d\d$", detail):
        return ""
    return detail.strip()


async def get_resolved_ip(domain: str) -> Optional[str]:
    """Получает IP адрес домена с одной попыткой переповтора при сбое."""
    try:
        loop = asyncio.get_running_loop()
        import socket as sock

        # Делаем до 2 попыток, если система вернула ошибку из-за перегрузки
        for attempt in range(2):
            try:
                addrs = await loop.getaddrinfo(
                    domain, 443, family=sock.AF_INET, type=sock.SOCK_STREAM
                )
                if addrs:
                    current_ip = addrs[0][4][0]
                    #console.print(f"[dim]{domain} -> {current_ip}[/dim]")
                    return current_ip
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(0.2) # Маленькая пауза перед второй попыткой
                    continue
                break
    except Exception:
        pass


def _classify_connect_error(error: httpx.ConnectError, bytes_read: int) -> Tuple[str, str, int]:
    """Глубокая классификация httpx.ConnectError."""
    full_text = _collect_error_text(error)
    err_errno = _get_errno_from_chain(error)

    # DNS ошибки
    gai = _find_cause_of_type(error, socket.gaierror)
    if gai is not None:
        gai_errno = getattr(gai, 'errno', None)
        if gai_errno in (socket.EAI_NONAME, 11001):
            return ("[yellow]DNS FAIL[/yellow]", "Домен не найден", bytes_read)
        elif gai_errno in (getattr(socket, 'EAI_AGAIN', -3), 11002):
            # Может быть как таймаут, так и дроп провайдером
            # Проверяем есть ли в тексте ошибки признаки дропа
            if "connection" in full_text and ("reset" in full_text or "refused" in full_text or "closed" in full_text):
                return ("[yellow]DNS FAIL[/yellow]", "DNS ошибка/дроп", bytes_read)
            return ("[yellow]DNS FAIL[/yellow]", "DNS таймаут/недоступен", bytes_read)
        else:
            return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    if any(x in full_text for x in ["getaddrinfo failed", "name resolution", "11001", "11002",
                                      "name or service not known", "nodename nor servname"]):
        return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    # TLS alert внутри ConnectError (DPI)
    if "sslv3_alert" in full_text or "ssl alert" in full_text or ("alert" in full_text and "handshake" in full_text):
        if "handshake_failure" in full_text or "handshake failure" in full_text:
            return ("[bold red]TLS DPI[/bold red]", "Handshake alert", bytes_read)
        elif "unrecognized_name" in full_text:
            return ("[bold red]TLS DPI[/bold red]", "SNI alert", bytes_read)
        elif "protocol_version" in full_text or "alert_protocol_version" in full_text:
            # Это может быть легитимная несовместимость версий
            return ("[bold red]TLS BLOCK[/bold red]", "Version alert", bytes_read)
        else:
            return ("[bold red]TLS DPI[/bold red]", "TLS alert", bytes_read)

    # ConnectionRefusedError
    if _find_cause_of_type(error, ConnectionRefusedError) is not None \
       or err_errno in (errno.ECONNREFUSED, WSAECONNREFUSED) \
       or "refused" in full_text:
        return ("[bold red]REFUSED[/bold red]", "Порт закрыт/RST", bytes_read)

    # ConnectionResetError
    if _find_cause_of_type(error, ConnectionResetError) is not None \
       or err_errno in (errno.ECONNRESET, WSAECONNRESET) \
       or "connection reset" in full_text:
        return ("[bold red]TCP RST[/bold red]", "RST при handshake", bytes_read)

    # ConnectionAbortedError
    if _find_cause_of_type(error, ConnectionAbortedError) is not None \
       or err_errno in (getattr(errno, 'ECONNABORTED', 103), WSAECONNABORTED) \
       or "connection aborted" in full_text:
        return ("[bold red]TCP ABORT[/bold red]", "Соединение прервано", bytes_read)

    # TimeoutError
    if _find_cause_of_type(error, TimeoutError) is not None \
       or err_errno in (errno.ETIMEDOUT, WSAETIMEDOUT) \
       or "timed out" in full_text:
        return ("[red]TIMEOUT[/red]", "Таймаут handshake", bytes_read)

    # Network unreachable
    if err_errno in (errno.ENETUNREACH, WSAENETUNREACH) or "network is unreachable" in full_text:
        return ("[red]NET UNREACH[/red]", "Сеть недоступна", bytes_read)
    if err_errno in (errno.EHOSTUNREACH, WSAEHOSTUNREACH) or "no route to host" in full_text:
        return ("[red]HOST UNREACH[/red]", "Хост недоступен", bytes_read)

    # SSL ошибки внутри ConnectError
    ssl_err = _find_cause_of_type(error, ssl.SSLError)
    if ssl_err is not None:
        return _classify_ssl_error(ssl_err, bytes_read)

    # All connection attempts failed
    if "all connection attempts failed" in full_text:
        return ("[bold red]CONN FAIL[/bold red]", "Все попытки провалились", bytes_read)

    short = str(error)[:40].replace("\n", " ")
    return ("[red]CONN ERR[/red]", _clean_detail(short), bytes_read)


def _classify_ssl_error(error: ssl.SSLError, bytes_read: int) -> Tuple[str, str, int]:
    """Детальная классификация ssl.SSLError с приоритетами."""
    error_msg = str(error).lower()

    # ============================================================================
    # ПРИОРИТЕТ 1: DPI МАНИПУЛЯЦИИ (самые важные для детектирования блокировок)
    # ============================================================================

    # DPI обрывает handshake или передачу данных
    dpi_interruption_markers = [
        "eof", "unexpected eof",                    # Linux: SSLEOFError
        "eof occurred in violation",                # Linux: точное описание
        "operation did not complete",               # Windows: SSLWantReadError
        "bad record mac",                           # Повреждённые TLS записи
        "decryption failed", "decrypt"              # Ошибки расшифровки
    ]

    if any(marker in error_msg for marker in dpi_interruption_markers):
        if bytes_read > 0:
            return ("[bold red]TLS DPI[/bold red]", "Обрыв при передаче", bytes_read)
        else:
            return ("[bold red]TLS DPI[/bold red]", "Обрыв handshake", bytes_read)

    # DPI манипулирует handshake
    if any(x in error_msg for x in [
        "illegal parameter",
        "decode error", "decoding error",
        "record overflow", "oversized",
        "record layer failure", "record_layer_failure",   # DPI повреждает TLS записи
        "bad key share", "bad_key_share"                 # Проблема с key exchange (часто AWS/CDN)
    ]):
        # Специальная обработка для AWS/CDN специфичных ошибок
        if "bad key share" in error_msg or "bad_key_share" in error_msg:
            return ("[yellow]SSL ERR[/yellow]", "[SSL] Bad key share", bytes_read)
        if "record layer failure" in error_msg or "record_layer_failure" in error_msg:
            return ("[yellow]SSL ERR[/yellow]", "[SSL] Record layer fail", bytes_read)
        # Остальные - это DPI
        return ("[bold red]TLS DPI[/bold red]", "Подмена handshake", bytes_read)

    # DPI блокирует по SNI
    if "unrecognized name" in error_msg or "unrecognized_name" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "SNI блок", bytes_read)

    # DPI отправляет TLS alert
    if "alert handshake" in error_msg or "sslv3_alert_handshake" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Handshake alert", bytes_read)

    # Общие handshake ошибки от DPI
    if "handshake" in error_msg:
        if "unexpected" in error_msg:
            return ("[bold red]TLS DPI[/bold red]", "HS подмена", bytes_read)
        elif "failure" in error_msg or "handshake failure" in error_msg:
            return ("[bold red]TLS DPI[/bold red]", "HS failure", bytes_read)

    # DPI отправляет не-TLS ответ
    if "wrong version number" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Non-TLS ответ", bytes_read)

    # ============================================================================
    # ПРИОРИТЕТ 2: MITM (Man-in-the-Middle атаки, подмена сертификатов)
    # ============================================================================

    # Проверка сертификата
    if isinstance(error, ssl.SSLCertVerificationError):
        verify_code = getattr(error, 'verify_code', None)
        if verify_code == 10 or "expired" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert expired", bytes_read)
        elif verify_code in (18, 19) or "self-signed" in error_msg or "self signed" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Self-signed", bytes_read)
        elif verify_code == 20 or "unknown ca" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Unknown CA", bytes_read)
        elif verify_code == 62 or "hostname mismatch" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Hostname mismatch", bytes_read)
        else:
            return ("[bold red]TLS MITM[/bold red]", "Cert fail", bytes_read)

    # Ошибки сертификата (общий случай)
    if "certificate" in error_msg:
        if "verify failed" in error_msg or "unknown ca" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Unknown CA", bytes_read)
        elif "hostname mismatch" in error_msg or "name mismatch" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert mismatch", bytes_read)
        elif "expired" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert expired", bytes_read)
        else:
            return ("[red]SSL CERT[/red]", "Cert error", bytes_read)

    # Несовпадение cipher suite (возможен MITM)
    if "cipher" in error_msg or "no shared cipher" in error_msg:
        return ("[bold red]TLS MITM[/bold red]", "Cipher mismatch", bytes_read)

    # ============================================================================
    # ПРИОРИТЕТ 3: БЛОКИРОВКА ВЕРСИИ / ПРОТОКОЛА
    # ============================================================================

    if "version" in error_msg or "protocol version" in error_msg:
        return ("[bold red]TLS BLOCK[/bold red]", "Version block", bytes_read)

    # ============================================================================
    # ПРИОРИТЕТ 4: КОРРЕКТНОЕ ЗАКРЫТИЕ / ТЕХНИЧЕСКИЕ ОШИБКИ
    # ============================================================================

    # Корректное закрытие TLS
    if isinstance(error, ssl.SSLZeroReturnError):
        return ("[bold red]TLS CLOSE[/bold red]", "Close notify", bytes_read)

    # Внутренняя ошибка SSL
    if "internal error" in error_msg:
        return ("[red]SSL INT[/red]", "Internal error", bytes_read)

    # Общие handshake ошибки (не DPI)
    if "handshake" in error_msg:
        return ("[red]TLS ERR[/red]", "Handshake error", bytes_read)

    # ============================================================================
    # FALLBACK: Неопознанные ошибки
    # ============================================================================

    short_msg = _clean_detail(str(error)[:40])
    return ("[red]SSL ERR[/red]", short_msg, bytes_read)


def _classify_read_error(error: Exception, bytes_read: int) -> Tuple[str, str, int]:
    """Классификация ошибок при чтении данных."""
    kb_read = math.ceil(bytes_read / 1024)
    full_text = _collect_error_text(error)
    err_errno = _get_errno_from_chain(error)

    is_tcp16_20_range = TCP_BLOCK_MIN_KB <= kb_read <= TCP_BLOCK_MAX_KB

    # ConnectionResetError
    if _find_cause_of_type(error, ConnectionResetError) is not None \
       or err_errno in (errno.ECONNRESET, WSAECONNRESET) \
       or "connection reset" in full_text:
        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"RST at {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI RESET[/bold red]", f"RST at {kb_read:.1f}KB", bytes_read)
        else:
            return ("[bold red]TCP RST[/bold red]", "RST before data", bytes_read)

    # ConnectionAbortedError
    if _find_cause_of_type(error, ConnectionAbortedError) is not None \
       or err_errno in (getattr(errno, 'ECONNABORTED', 103), WSAECONNABORTED) \
       or "connection aborted" in full_text:
        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"Abort at {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI ABORT[/bold red]", f"Abort at {kb_read:.1f}KB", bytes_read)
        else:
            return ("[bold red]TCP ABORT[/bold red]", "Abort before data", bytes_read)

    # BrokenPipeError
    if _find_cause_of_type(error, BrokenPipeError) is not None \
       or err_errno == errno.EPIPE \
       or "broken pipe" in full_text:
        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"Pipe broken {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI PIPE[/bold red]", f"Pipe {kb_read:.1f}KB", bytes_read)
        else:
            return ("[bold red]BROKEN PIPE[/bold red]", "Pipe broken", bytes_read)

    # RemoteProtocolError
    if isinstance(error, httpx.RemoteProtocolError) or "remoteprotocolerror" in full_text:
        if "peer closed" in full_text or "connection closed" in full_text:
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"FIN at {kb_read:.1f}KB", bytes_read)
            elif kb_read > 0:
                return ("[bold red]DPI CLOSE[/bold red]", f"Closed at {kb_read:.1f}KB", bytes_read)
            else:
                return ("[bold red]PEER CLOSE[/bold red]", "Closed early", bytes_read)
        elif "incomplete" in full_text:
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"Incomplete {kb_read:.1f}KB", bytes_read)
            elif kb_read > 0:
                return ("[bold red]DPI TRUNC[/bold red]", f"Truncated {kb_read:.1f}KB", bytes_read)
            else:
                return ("[bold red]INCOMPLETE[/bold red]", "Incomplete response", bytes_read)
        else:
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"Proto err {kb_read:.1f}KB", bytes_read)
            elif kb_read > 0:
                return ("[bold red]DPI PROTO[/bold red]", f"Proto err {kb_read:.1f}KB", bytes_read)
            else:
                return ("[red]PROTO ERR[/red]", "Protocol error", bytes_read)

    # httpx.ReadError
    if isinstance(error, httpx.ReadError):
        ssl_err = _find_cause_of_type(error, ssl.SSLError)
        if ssl_err is not None:
            label, detail, _ = _classify_ssl_error(ssl_err, bytes_read)
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"TLS err {kb_read:.1f}KB", bytes_read)
            return (label, f"{detail} at {kb_read:.1f}KB" if kb_read > 0 else detail, bytes_read)

        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"Read err {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI RESET[/bold red]", f"Read err {kb_read:.1f}KB", bytes_read)
        else:
            return ("[red]READ ERR[/red]", "Read error", bytes_read)

    # Fallback
    if is_tcp16_20_range:
        return ("[bold red]TCP16-20[/bold red]", f"Error at {kb_read:.1f}KB", bytes_read)
    elif kb_read > 0:
        return ("[bold red]DPI RESET[/bold red]", f"Error at {kb_read:.1f}KB", bytes_read)
    else:
        return ("[red]READ ERR[/red]", f"{type(error).__name__}", bytes_read)


async def check_tcp_tls_single(
    domain: str, tls_version: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str, int, float]:
    """Одиночная проверка TCP/TLS с DEBUG режимом."""
    bytes_read = 0

    should_debug = DEBUG_MODE and (not DEBUG_DOMAINS or domain in DEBUG_DOMAINS)

    if should_debug:
        debug_log(f"Starting check for {domain} with {tls_version}", "DEBUG")

    async with semaphore:
        start_time = time.time()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if should_debug:
            debug_log(f"OpenSSL version: {ssl.OPENSSL_VERSION}", "DEBUG")
            debug_log(f"Python SSL module: {ssl.get_default_verify_paths()}", "DEBUG")

        if tls_version == "TLSv1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif tls_version == "TLSv1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        transport = httpx.AsyncHTTPTransport(verify=ctx, http2=False, retries=0)

        try:
            async with httpx.AsyncClient(
                transport=transport, timeout=TIMEOUT, follow_redirects=False
            ) as client:
                try:
                    req = client.build_request(
                        "GET",
                        f"https://{domain}",
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept-Encoding": "identity",
                            "Connection": "close"
                        }
                    )

                    if should_debug:
                        debug_log(f"Request URL: {req.url}", "DEBUG")
                        debug_log(f"Request headers: {dict(req.headers)}", "DEBUG")

                    response = await client.send(req, stream=True)
                    status_code = response.status_code
                    location = response.headers.get("location", "")

                    if should_debug:
                        debug_log(f"Response status: {status_code}", "SUCCESS")
                        debug_log(f"Response headers: {dict(response.headers)}", "DEBUG")

                    # HTTP 451 - официальная блокировка
                    if status_code == 451:
                        await response.aclose()
                        elapsed = time.time() - start_time
                        return ("[bold red]BLOCKED[/bold red]", "HTTP 451", bytes_read, elapsed)

                    # Умная проверка редиректов
                    if location:
                        location_lower = location.lower()

                        # Явные маркеры блок-страниц
                        if any(marker in location_lower for marker in BLOCK_MARKERS):
                            await response.aclose()
                            elapsed = time.time() - start_time
                            return ("[bold red]ISP PAGE[/bold red]", "Редирект на блок-страницу", bytes_read, elapsed)

                        # Проверяем домен редиректа
                        try:
                            parsed_location = urlparse(location if location.startswith('http') else f'https://{location}')
                            location_domain = parsed_location.netloc.lower()

                            clean_domain = domain.lower().replace('www.', '')
                            clean_location = location_domain.replace('www.', '')

                            # Редирект на другой домен (не поддомен)
                            if location_domain and clean_location != clean_domain and not clean_location.endswith('.' + clean_domain):
                                # Исключения: CDN, авторизация
                                legitimate_patterns = [
                                    'cloudflare', 'akamai', 'fastly', 'cdn', 'cloudfront',
                                    'auth', 'login', 'accounts', 'id.', 'sso.',
                                ]

                                is_legitimate = any(pattern in clean_location for pattern in legitimate_patterns)

                                if not is_legitimate:
                                    await response.aclose()
                                    elapsed = time.time() - start_time
                                    return ("[bold red]ISP PAGE[/bold red]", f"→ {location_domain[:20]}", bytes_read, elapsed)
                        except Exception:
                            pass

                    # Редирект (это OK)
                    if 300 <= status_code < 400:
                        await response.aclose()
                        elapsed = time.time() - start_time
                        return ("[green]OK[/green]", "", bytes_read, elapsed)

                    elapsed = time.time() - start_time

                    # Проверка тела на блок-страницу только для малых ответов
                    if status_code == 200:
                        content_length = response.headers.get("content-length", "")
                        try:
                            content_len = int(content_length) if content_length else 0
                        except:
                            content_len = 0

                        if content_len > 0 and content_len < BODY_INSPECT_LIMIT:
                            body_bytes = b""
                            try:
                                async for chunk in response.aiter_bytes(chunk_size=128):
                                    body_bytes += chunk
                                    if len(body_bytes) >= BODY_INSPECT_LIMIT:
                                        break
                            except Exception:
                                pass

                            body_text = body_bytes.decode("utf-8", errors="ignore").lower()
                            if any(m in body_text for m in BODY_BLOCK_MARKERS):
                                await response.aclose()
                                return ("[bold red]ISP PAGE[/bold red]", "Блок-страница в теле", len(body_bytes), elapsed)

                    await response.aclose()

                    # Любой HTTP 2xx-4xx - это OK
                    if 200 <= status_code < 500:
                        return ("[green]OK[/green]", "", bytes_read, elapsed)
                    else:
                        return ("[green]OK[/green]", f"HTTP {status_code}", bytes_read, elapsed)

                except httpx.ConnectTimeout as e:
                    if should_debug:
                        debug_exception(e, domain, f"{tls_version} - ConnectTimeout")
                    elapsed = time.time() - start_time
                    return ("[red]TIMEOUT[/red]", "Таймаут handshake", bytes_read, elapsed)

                except httpx.ConnectError as e:
                    if should_debug:
                        debug_exception(e, domain, f"{tls_version} - ConnectError")
                    label, detail, br = _classify_connect_error(e, bytes_read)
                    elapsed = time.time() - start_time
                    return (label, detail, br, elapsed)

                except httpx.ReadTimeout as e:
                    if should_debug:
                        debug_exception(e, domain, f"{tls_version} - ReadTimeout")
                    kb_read = math.ceil(bytes_read / 1024)
                    elapsed = time.time() - start_time
                    if TCP_BLOCK_MIN_KB <= kb_read <= TCP_BLOCK_MAX_KB:
                        return ("[bold red]TCP16-20[/bold red]", f"Timeout {kb_read:.1f}KB", bytes_read, elapsed)
                    if kb_read > 0:
                        return ("[red]TIMEOUT[/red]", f"Read timeout {kb_read:.1f}KB", bytes_read, elapsed)
                    return ("[red]TIMEOUT[/red]", "Read timeout", bytes_read, elapsed)

        except ssl.SSLError as e:
            if should_debug:
                debug_exception(e, domain, f"{tls_version} - SSLError")
            label, detail, br = _classify_ssl_error(e, bytes_read)
            elapsed = time.time() - start_time
            return (label, detail, br, elapsed)

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            if should_debug:
                debug_exception(e, domain, f"{tls_version} - Connection Error")
            label, detail, br = _classify_read_error(e, bytes_read)
            elapsed = time.time() - start_time
            return (label, detail, br, elapsed)

        except OSError as e:
            if should_debug:
                debug_exception(e, domain, f"{tls_version} - OSError")
            elapsed = time.time() - start_time
            err_num = e.errno
            if err_num in (errno.ECONNRESET, WSAECONNRESET):
                return ("[bold red]TCP RST[/bold red]", "OS conn reset", bytes_read, elapsed)
            elif err_num in (errno.ECONNREFUSED, WSAECONNREFUSED):
                return ("[bold red]REFUSED[/bold red]", "OS conn refused", bytes_read, elapsed)
            elif err_num in (errno.ETIMEDOUT, WSAETIMEDOUT):
                return ("[red]TIMEOUT[/red]", "OS timeout", bytes_read, elapsed)
            else:
                return ("[red]OS ERR[/red]", f"errno={err_num}", bytes_read, elapsed)

        except Exception as e:
            if should_debug:
                debug_exception(e, domain, f"{tls_version} - Unexpected Exception")
            elapsed = time.time() - start_time
            return ("[red]ERR[/red]", f"{type(e).__name__}", bytes_read, elapsed)


async def check_tcp_tls(
    domain: str, tls_version: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str, float]:
    """Множественная проверка TCP/TLS."""
    results = []

    for attempt in range(DOMAIN_CHECK_RETRIES):
        status, detail, bytes_read, elapsed = await check_tcp_tls_single(
            domain, tls_version, semaphore
        )
        results.append((status, detail, bytes_read, elapsed))

        if attempt < DOMAIN_CHECK_RETRIES - 1:
            await asyncio.sleep(0.1)

    # Приоритет критическим ошибкам
    critical_markers = [
        "TCP16-20", "DPI RESET", "DPI ABORT", "DPI CLOSE", "ISP PAGE",
        "BLOCKED", "TCP RST", "TCP ABORT", "TLS MITM", "TLS DPI", "TLS BLOCK",
    ]
    for status, detail, _, elapsed in results:
        if any(marker in status for marker in critical_markers):
            return (status, detail, elapsed)

    # Любые другие не-OK
    for status, detail, _, elapsed in results:
        if "OK" not in status:
            return (status, detail, elapsed)

    return (results[0][0], results[0][1], results[0][3])


async def check_http_injection(
    domain: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str]:
    """Проверка HTTP-инжекции. Семафор захватывается снаружи (в http_phase_worker)."""
    try:
        clean_domain = domain.replace("https://", "").replace("http://", "")

        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=False
        ) as client:
            req = client.build_request(
                "GET",
                f"http://{clean_domain}",
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept-Encoding": "identity",
                    "Connection": "close"
                }
            )
            response = await client.send(req, stream=True)
            status_code = response.status_code
            location = response.headers.get("location", "")

            if status_code == 451:
                await response.aclose()
                return ("[bold red]BLOCKED[/bold red]", "HTTP 451")

            if any(marker in location.lower() for marker in BLOCK_MARKERS):
                await response.aclose()
                return ("[bold red]ISP PAGE[/bold red]", "Блок-страница")

            # Проверка тела для 200 OK
            if 200 <= status_code < 300:
                body_bytes = b""
                try:
                    async for chunk in response.aiter_bytes(chunk_size=128):
                        body_bytes += chunk
                        if len(body_bytes) >= BODY_INSPECT_LIMIT:
                            break
                except Exception:
                    pass
                await response.aclose()

                body_text = body_bytes.decode("utf-8", errors="ignore").lower()
                if any(m in body_text for m in BODY_BLOCK_MARKERS):
                    return ("[bold red]ISP PAGE[/bold red]", "Блок-страница (HTTP)")
                return ("[green]OK[/green]", f"{status_code}")

            # Редирект - OK
            if 300 <= status_code < 400:
                await response.aclose()
                return ("[green]REDIR[/green]", f"{status_code}")

            await response.aclose()
            return ("[green]OK[/green]", f"{status_code}")

    except httpx.ConnectTimeout:
        return ("[red]TIMEOUT[/red]", "Connect timeout")

    except httpx.ReadTimeout:
        return ("[red]TIMEOUT[/red]", "Read timeout")

    except httpx.WriteTimeout:
        return ("[red]TIMEOUT[/red]", "Write timeout")

    except httpx.PoolTimeout:
        return ("[red]TIMEOUT[/red]", "Pool timeout")

    except httpx.ConnectError as e:
        full_text = _collect_error_text(e)
        if _find_cause_of_type(e, socket.gaierror) is not None \
           or any(x in full_text for x in ["getaddrinfo", "name resolution"]):
            return ("[yellow]DNS FAIL[/yellow]", "DNS error")
        if _find_cause_of_type(e, ConnectionRefusedError) is not None \
           or "refused" in full_text:
            return ("[red]REFUSED[/red]", "Refused")
        if _find_cause_of_type(e, ConnectionResetError) is not None \
           or "reset" in full_text:
            return ("[red]TCP RST[/red]", "RST")
        if _find_cause_of_type(e, TimeoutError) is not None \
           or "timed out" in full_text:
            return ("[red]TIMEOUT[/red]", "Timeout")
        return ("[red]CONN ERR[/red]", "Conn error")

    except httpx.ReadError as e:
        full_text = _collect_error_text(e)
        err_errno = _get_errno_from_chain(e)
        if _find_cause_of_type(e, ConnectionResetError) is not None \
           or err_errno in (errno.ECONNRESET, WSAECONNRESET) \
           or "connection reset" in full_text:
            return ("[red]TCP RST[/red]", "RST on read")
        if _find_cause_of_type(e, ConnectionAbortedError) is not None \
           or err_errno in (getattr(errno, 'ECONNABORTED', 103), WSAECONNABORTED):
            return ("[red]TCP ABORT[/red]", "Abort on read")
        return ("[red]READ ERR[/red]", "Read error")

    except httpx.RemoteProtocolError as e:
        full_text = _collect_error_text(e)
        if "peer closed" in full_text or "connection closed" in full_text:
            return ("[red]TCP RST[/red]", "Peer closed")
        return ("[red]PROTO ERR[/red]", "Protocol error")

    except httpx.TimeoutException:
        return ("[red]TIMEOUT[/red]", "Timeout")

    except OSError as e:
        err_num = e.errno
        if err_num in (errno.ECONNRESET, WSAECONNRESET):
            return ("[red]TCP RST[/red]", "OS conn reset")
        if err_num in (errno.ECONNREFUSED, WSAECONNREFUSED):
            return ("[red]REFUSED[/red]", "OS conn refused")
        if err_num in (errno.ETIMEDOUT, WSAETIMEDOUT):
            return ("[red]TIMEOUT[/red]", "OS timeout")
        if err_num in (errno.ENETUNREACH, WSAENETUNREACH):
            return ("[red]NET UNREACH[/red]", "Network unreachable")
        return ("[red]OS ERR[/red]", f"errno={err_num}")

    except Exception as e:
        full_text = _collect_error_text(e)
        if "timeout" in full_text or "timed out" in full_text:
            return ("[red]TIMEOUT[/red]", "Timeout")
        if "reset" in full_text:
            return ("[red]TCP RST[/red]", "RST")
        if "refused" in full_text:
            return ("[red]REFUSED[/red]", "Refused")
        return ("[red]HTTP ERR[/red]", f"{type(e).__name__}")





async def check_tcp_16_20_single(
    url: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str, int]:
    """Одиночная проверка TCP 16-20KB лимита."""
    bytes_read = 0

    async with semaphore:
        start_time = time.time()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        transport = httpx.AsyncHTTPTransport(verify=ctx, http2=False, retries=0)

        try:
            async with httpx.AsyncClient(
                transport=transport, timeout=TIMEOUT_TCP_16_20, follow_redirects=False
            ) as client:
                req = client.build_request(
                    "GET",
                    url,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept-Encoding": "identity",
                        "Connection": "close"
                    }
                )
                response = await client.send(req, stream=True)

                try:
                    async for chunk in response.aiter_bytes(chunk_size=128):
                        bytes_read += len(chunk)
                        if bytes_read >= DATA_READ_THRESHOLD:
                            await response.aclose()
                            elapsed = time.time() - start_time
                            return (
                                "[green]OK[/green]",
                                f"{elapsed:.1f}s",
                                bytes_read,
                            )

                    await response.aclose()
                    elapsed = time.time() - start_time
                    return (
                        "[green]OK[/green]",
                        f"{elapsed:.1f}s",
                        bytes_read,
                    )

                except (
                    httpx.ReadError,
                    httpx.RemoteProtocolError,
                    ConnectionResetError,
                    ConnectionAbortedError,
                    BrokenPipeError,
                ) as e:
                    kb_read = math.ceil(bytes_read / 1024)
                    full_text = _collect_error_text(e)
                    err_errno = _get_errno_from_chain(e)

                    if _find_cause_of_type(e, ConnectionResetError) is not None \
                       or err_errno in (errno.ECONNRESET, WSAECONNRESET) \
                       or "connection reset" in full_text:
                        error_detail = "RST by peer"
                    elif _find_cause_of_type(e, ConnectionAbortedError) is not None \
                         or err_errno in (getattr(errno, 'ECONNABORTED', 103), WSAECONNABORTED):
                        error_detail = "Connection aborted"
                    elif _find_cause_of_type(e, BrokenPipeError) is not None \
                         or err_errno == errno.EPIPE:
                        error_detail = "Broken pipe"
                    elif isinstance(e, httpx.RemoteProtocolError):
                        if "peer closed" in full_text:
                            error_detail = "Peer sent FIN"
                        elif "incomplete" in full_text:
                            error_detail = "Incomplete response"
                        else:
                            error_detail = "Protocol error"
                    else:
                        ssl_err = _find_cause_of_type(e, ssl.SSLError)
                        if ssl_err is not None:
                            _, ssl_detail, _ = _classify_ssl_error(ssl_err, bytes_read)
                            error_detail = f"TLS: {ssl_detail}"
                        else:
                            error_detail = _clean_detail(str(e)[:50])

                    if kb_read > 0:
                        return (
                            "[bold red]DETECTED[/bold red]",
                            f"Dropped at {kb_read:.0f}KB — {error_detail}",
                            bytes_read,
                        )
                    else:
                        return (
                            "[red]CONN ERR[/red]",
                            f"Failed: {error_detail}",
                            bytes_read,
                        )

        except httpx.ConnectTimeout:
            return ("[red]TIMEOUT[/red]", "Handshake timeout", bytes_read)

        except httpx.ConnectError as e:
            status, detail, br = _classify_connect_error(e, bytes_read)
            return (status, detail, br)

        except httpx.ReadTimeout:
            kb_read = math.ceil(bytes_read / 1024)
            if kb_read > 0:
                return (
                    "[bold red]DETECTED[/bold red]",
                    f"Read timeout at {kb_read:.0f}KB",
                    bytes_read,
                )
            return ("[red]TIMEOUT[/red]", "Read timeout", bytes_read)

        except ssl.SSLError as e:
            label, detail, br = _classify_ssl_error(e, bytes_read)
            return (label, detail, br)

        except OSError as e:
            kb_read = math.ceil(bytes_read / 1024)
            err_num = e.errno
            if err_num in (errno.ECONNRESET, WSAECONNRESET):
                if kb_read > 0:
                    return (
                        "[bold red]DETECTED[/bold red]",
                        f"OS conn reset at {kb_read:.0f}KB",
                        bytes_read,
                    )
                return ("[bold red]TCP RST[/bold red]", "OS conn reset", bytes_read)
            else:
                return ("[red]OS ERR[/red]", f"errno={err_num}", bytes_read)

        except Exception as e:
            kb_read = math.ceil(bytes_read / 1024)
            error_detail = f"{type(e).__name__}"
            if kb_read > 0:
                return (
                    "[red]ERROR[/red]",
                    f"Error at {kb_read:.0f}KB — {error_detail}",
                    bytes_read,
                )
            return ("[red]ERROR[/red]", error_detail, bytes_read)


async def check_tcp_16_20(
    url: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str]:
    """Проверка TCP 16-20KB лимита с множественными попытками."""
    results = []

    for attempt in range(TCP_16_20_CHECK_RETRIES):
        status, detail, bytes_read = await check_tcp_16_20_single(url, semaphore)
        results.append((status, detail, bytes_read))

        if attempt < TCP_16_20_CHECK_RETRIES - 1:
            await asyncio.sleep(0.1)

    # Приоритизируем ошибки
    for status, detail, _ in results:
        if "DETECTED" in status:
            return (status, detail)

    for status, detail, _ in results:
        if "OK" not in status:
            return (status, detail)

    # Проверка на балансировку DPI стратегий
    if TCP_16_20_CHECK_RETRIES > 1:
        ok_count = sum(1 for s, _, _ in results if "OK" in s)
        error_count = len(results) - ok_count

        if ok_count > 0 and error_count > 0:
            variance_percent = (error_count / len(results)) * 100
            if variance_percent >= DPI_VARIANCE_THRESHOLD:
                return (
                    "[bold yellow]MIXED RESULTS[/bold yellow]",
                    f"{ok_count} OK, {error_count} blocked — возможная балансировка DPI",
                )

    return (results[0][0], results[0][1])

def clean_hostname(url_or_domain: str) -> str:
    """Очищает строку, оставляя только домен (без протокола, пути и порта)."""
    url_or_domain = url_or_domain.strip().lower()

    # Если в строке нет протокола, urlparse может отработать некорректно.
    # Добавляем временный протокол для корректного парсинга.
    if "://" not in url_or_domain:
        url_or_domain = "http://" + url_or_domain

    parsed = urlparse(url_or_domain)
    host = parsed.netloc # Здесь будет 'example.com' или 'example.com:443'

    # Убираем порт, если он указан (например, example.com:443 -> example.com)
    if ":" in host:
        host = host.split(":")[0]

    return host

async def resolve_worker(domain_raw: str, semaphore: asyncio.Semaphore, stub_ips: set) -> dict:
    """Фаза 0: DNS-резолв домена. Возвращает словарь с начальным состоянием записи."""
    domain = clean_hostname(domain_raw)
    async with semaphore:
        resolved_ip = await get_resolved_ip(domain)

    entry = {
        "domain": domain,
        "resolved_ip": resolved_ip,
        "dns_fake": False,
        "t13_res": ("[dim]—[/dim]", "", 0.0),
        "t12_res": ("[dim]—[/dim]", "", 0.0),
        "http_res": ("[dim]—[/dim]", ""),
    }

    if resolved_ip is None:
        fail = "[yellow]DNS FAIL[/yellow]"
        entry["t13_res"] = (fail, "Домен не найден", 0.0)
        entry["t12_res"] = (fail, "Домен не найден", 0.0)
        entry["http_res"] = (fail, "Домен не найден")
        entry["dns_fake"] = None  # sentinel: DNS failed
    elif stub_ips and resolved_ip in stub_ips:
        fake = "[bold red]DNS FAKE[/bold red]"
        detail = f"DNS подмена -> {resolved_ip}"
        entry["t13_res"] = (fake, detail, 0.0)
        entry["t12_res"] = (fake, detail, 0.0)
        entry["http_res"] = (fake, detail)
        entry["dns_fake"] = True

    return entry


async def tls_phase_worker(entry: dict, tls_version: str, semaphore: asyncio.Semaphore) -> None:
    """Фаза TLS: проверяет один домен одной версией TLS, пишет результат в entry in-place."""
    # Пропускаем домены с проблемами DNS
    if entry["dns_fake"] is not False:
        return

    domain = entry["domain"]
    key = "t13_res" if tls_version == "TLSv1.3" else "t12_res"
    try:
        result = await check_tcp_tls(domain, tls_version, semaphore)
    except Exception:
        result = ("[dim]ERR[/dim]", "Unknown error", 0.0)
    entry[key] = result


async def http_phase_worker(entry: dict, semaphore: asyncio.Semaphore) -> None:
    """Фаза HTTP: проверяет HTTP-инжекцию для одного домена, пишет результат в entry in-place."""
    if entry["dns_fake"] is not False:
        return

    domain = entry["domain"]
    async with semaphore:
        try:
            result = await check_http_injection(domain, semaphore)
        except Exception:
            result = ("[dim]ERR[/dim]", "Unknown error")
    entry["http_res"] = result


def _build_row(entry: dict) -> list:
    """Собирает финальную строку таблицы из entry."""
    domain = entry["domain"]
    t12_status, t12_detail, t12_elapsed = entry["t12_res"]
    t13_status, t13_detail, t13_elapsed = entry["t13_res"]
    http_status, http_detail = entry["http_res"]

    details = []
    d12 = _clean_detail(t12_detail)
    d13 = _clean_detail(t13_detail)

    if d12 or d13:
        if d12 == d13:
            details.append(d12)
        else:
            if d12: details.append(f"T12:{d12}")
            if d13: details.append(f"T13:{d13}")

    request_time = min(t for t in (t12_elapsed, t13_elapsed) if t > 0) if any(t > 0 for t in (t12_elapsed, t13_elapsed)) else 0
    if request_time > 0:
        details.append(f"{request_time:.1f}s")

    detail_str = " | ".join([d for d in details if d])
    return [domain, t12_status, t13_status, http_status, detail_str, entry["resolved_ip"]]


async def tcp_16_20_worker(item: dict, semaphore: asyncio.Semaphore, stub_ips: set = None):
    if stub_ips is None:
        stub_ips = set()

    # Извлекаем домен из URL
    from urllib.parse import urlparse
    parsed = urlparse(item["url"])
    domain = parsed.hostname or parsed.path.split('/')[0]

    # Получаем resolved IP
    resolved_ip = await get_resolved_ip(domain)

    status, error_detail = await check_tcp_16_20(item["url"], semaphore)

    # Проверка на DNS заглушку
    if resolved_ip and stub_ips and resolved_ip in stub_ips:
        status = "[bold red]DNS FAKE[/bold red]"
        error_detail = f"DNS подмена -> {resolved_ip}"

    asn_raw = str(item.get("asn", "")).strip()
    if asn_raw and not asn_raw.upper().startswith("AS"):
        asn_str = f"AS{asn_raw}"
    else:
        asn_str = asn_raw.upper() if asn_raw else "-"

    return [item["id"], asn_str, item["provider"], status, error_detail, resolved_ip]


async def _collect_stub_ips_silently() -> set:
    """Тихо собирает IP заглушек, перебирая серверы из конфига до первого успеха."""
    stub_ips = set()
    google_dns_ips_collection = {}

    # Пытаемся найти хотя бы один рабочий UDP сервер
    probe = None
    for udp_ip, name in DNS_UDP_SERVERS:
        try:
            probe = await _probe_dns_server(udp_ip, DNS_CHECK_DOMAINS)
            # Если хотя бы один домен разрешился, считаем сервер рабочим
            if probe["ok"] > 0:
                break
        except Exception:
            continue

    if probe and probe["results"]:
        # Собираем статистику по IP
        ip_domain_count = {}
        for domain, res in probe["results"].items():
            if isinstance(res, list):
                for ip in res:
                    ip_domain_count[ip] = ip_domain_count.get(ip, 0) + 1

        # IP, который вернулся для 2+ разных доменов — это заглушка
        for ip, count in ip_domain_count.items():
            if count >= 2:
                stub_ips.add(ip)

    return stub_ips


async def ask_test_selection() -> str:
    """Запрашивает у пользователя выбор тестов."""
    valid = {"1", "2", "3", "12", "13", "23", "123"}
    console.print(
        "\n[bold]Какие тесты запустить?[/bold]\n"
        "  [cyan]1[/cyan]   — DNS целостность\n"
        "  [cyan]2[/cyan]   — Проверка доменов (TLS + HTTP injection)\n"
        "  [cyan]3[/cyan]   — TCP 16-20KB блокировка\n"
        "  [cyan]123[/cyan] — Все тесты [dim](по умолчанию)[/dim]"
    )
    loop = asyncio.get_running_loop()
    try:
        raw = (await loop.run_in_executor(None, lambda: input("\nВведите выбор [123]: "))).strip()
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt

    if raw == "":
        return "123"
    if raw in valid:
        return raw

    console.print("[yellow]Неверный ввод, запускаем все тесты.[/yellow]")
    return "123"


async def run_domains_test(semaphore: asyncio.Semaphore, stub_ips: set) -> dict:
    """Тест 2: проверка доменов (TLS1.3 → TLS1.2 → HTTP), горизонтальное сканирование.
    Возвращает словарь со статистикой для итогового вывода."""
    console.print(
        "\n[bold]Проверка доменов (TLS + HTTP injection)[/bold]\n"
    )

    table = Table(
        show_header=True, header_style="bold magenta", border_style="dim"
    )
    table.add_column("Домен", style="cyan", no_wrap=True, width=18)
    table.add_column("TLS1.2", justify="center")
    table.add_column("TLS1.3", justify="center")
    table.add_column("HTTP", justify="center")
    table.add_column("Детали", style="dim", no_wrap=True)

    # ── Фаза 0: DNS-резолв всех доменов ──────────────────────────────────────
    entries: list[dict] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id = progress.add_task("Фаза 0/3: DNS-резолв...", total=len(DOMAINS))
        dns_tasks = [resolve_worker(d, semaphore, stub_ips) for d in DOMAINS]
        completed = 0
        for future in asyncio.as_completed(dns_tasks):
            entry = await future
            entries.append(entry)
            completed += 1
            progress.update(
                task_id,
                completed=completed,
                description=f"Фаза 0/3: DNS-резолв ({completed}/{len(DOMAINS)})...",
            )

    entries.sort(key=lambda e: e["domain"])

    # ── Фаза 1: TLS 1.3 ───────────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id = progress.add_task("Фаза 1/3: TLS 1.3...", total=len(entries))
        t13_tasks = [tls_phase_worker(e, "TLSv1.3", semaphore) for e in entries]
        completed = 0
        for future in asyncio.as_completed(t13_tasks):
            await future
            completed += 1
            progress.update(
                task_id,
                completed=completed,
                description=f"Фаза 1/3: TLS 1.3 ({completed}/{len(entries)})...",
            )

    # ── Фаза 2: TLS 1.2 ───────────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id = progress.add_task("Фаза 2/3: TLS 1.2...", total=len(entries))
        t12_tasks = [tls_phase_worker(e, "TLSv1.2", semaphore) for e in entries]
        completed = 0
        for future in asyncio.as_completed(t12_tasks):
            await future
            completed += 1
            progress.update(
                task_id,
                completed=completed,
                description=f"Фаза 2/3: TLS 1.2 ({completed}/{len(entries)})...",
            )

    # ── Фаза 3: HTTP injection ─────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id = progress.add_task("Фаза 3/3: HTTP...", total=len(entries))
        http_tasks = [http_phase_worker(e, semaphore) for e in entries]
        completed = 0
        for future in asyncio.as_completed(http_tasks):
            await future
            completed += 1
            progress.update(
                task_id,
                completed=completed,
                description=f"Фаза 3/3: HTTP ({completed}/{len(entries)})...",
            )

    results = [_build_row(e) for e in entries]
    results.sort(key=lambda x: x[0])

    dns_fail_count = 0
    resolved_ips_counter = {}

    for r in results:
        if len(r) > 5:
            resolved_ip = r[5]
            if resolved_ip and stub_ips and resolved_ip in stub_ips:
                resolved_ips_counter[resolved_ip] = resolved_ips_counter.get(resolved_ip, 0) + 1
        if "DNS FAIL" in r[1] or "DNS FAIL" in r[2] or "DNS FAIL" in r[3]:
            dns_fail_count += 1

    for r in results:
        table.add_row(*r[:5])

    console.print(table)

    confirmed_stubs = {
        ip: count for ip, count in resolved_ips_counter.items()
        if stub_ips and ip in stub_ips
    }

    if confirmed_stubs or dns_fail_count > 0:
        console.print(f"\n[bold yellow][i] ВОЗМОЖНО НЕ НАСТРОЕН DoH:[/bold yellow]")
        if confirmed_stubs:
            ips_text = [f"[red]{ip}[/red] у {count} домен(ов)" for ip, count in confirmed_stubs.items()]
            console.print(f"DNS вернул IP заглушки: {', '.join(ips_text)}")
        if dns_fail_count > 0:
            console.print(f"У {dns_fail_count} сайтов обнаружен DNS FAIL (Домен не найден)")
        console.print("[yellow]Рекомендация: Настройте DoH/DoT на вашем устройстве, роутере или VPN[/yellow]\n")

    ok_count      = sum(1 for r in results if "OK" in r[1] or "OK" in r[2])
    blocked_count = sum(1 for r in results if any(
        m in r[1] or m in r[2] or m in r[3]
        for m in ("TLS DPI", "TLS MITM", "TLS BLOCK", "ISP PAGE", "BLOCKED", "TCP RST", "TCP ABORT")
    ))
    timeout_count = sum(1 for r in results if "TIMEOUT" in r[1] or "TIMEOUT" in r[2])
    dns_fail_count_local = sum(1 for r in results if "DNS FAIL" in r[1])

    return {
        "total": len(DOMAINS),
        "ok": ok_count,
        "blocked": blocked_count,
        "timeout": timeout_count,
        "dns_fail": dns_fail_count_local,
    }


async def run_tcp_test(semaphore: asyncio.Semaphore, stub_ips: set) -> dict:
    """Тест 3: TCP 16-20KB блокировка. Возвращает словарь со статистикой."""
    console.print("\n[bold]Проверка TCP 16-20KB блока[/bold]")
    console.print(
        "[dim]Тестирование обрыва соединения после передачи 14-34KB)[/dim]\n"
    )

    tcp_table = Table(
        show_header=True, header_style="bold magenta", border_style="dim"
    )
    tcp_table.add_column("ID", style="white")
    tcp_table.add_column("ASN", style="yellow", justify="center")
    tcp_table.add_column("Провайдер", style="cyan")
    tcp_table.add_column("Статус", justify="center")
    tcp_table.add_column("Детали", style="dim")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id = progress.add_task(
            "Проверка TCP 16-20KB...", total=len(TCP_16_20_ITEMS)
        )
        tasks = [tcp_16_20_worker(item, semaphore, stub_ips) for item in TCP_16_20_ITEMS]

        tcp_results = []
        completed = 0
        for future in asyncio.as_completed(tasks):
            res = await future
            tcp_results.append(res)
            completed += 1
            progress.update(
                task_id,
                completed=completed,
                description=f"Проверка TCP 16-20KB ({completed}/{len(TCP_16_20_ITEMS)})...",
            )

    def get_group_name(provider_str):
        clean = re.sub(r'[^\w\s\.-]', '', provider_str).strip()
        parts = clean.split()
        return parts[0] if parts else clean

    provider_counts = {}
    for row in tcp_results:
        group = get_group_name(row[2])
        provider_counts[group] = provider_counts.get(group, 0) + 1

    def sort_key(row):
        group = get_group_name(row[2])
        count = provider_counts.get(group, 0)
        try:
            id_num = int(row[0].split('-')[-1])
        except (ValueError, IndexError):
            id_num = 99999
        return (-count, group, id_num)

    tcp_results.sort(key=sort_key)

    passed = sum(1 for r in tcp_results if "OK" in r[3])
    blocked = sum(1 for r in tcp_results if "DETECTED" in r[3])
    mixed = sum(1 for r in tcp_results if "MIXED RESULTS" in r[3])

    tcp_dns_fail_count = 0
    tcp_resolved_ips_counter = {}

    for r in tcp_results:
        if len(r) > 5 and r[5]:
            tcp_resolved_ips_counter[r[5]] = tcp_resolved_ips_counter.get(r[5], 0) + 1
        status_col = r[3]
        detail_col = r[4]
        if (
            "DNS" in status_col or "DNS" in detail_col or
            "FAIL" in status_col or "не найден" in detail_col or
            "not known" in detail_col
        ):
            tcp_dns_fail_count += 1

    for r in tcp_results:
        tcp_table.add_row(*r[:5])

    console.print(tcp_table)

    tcp_confirmed_stubs = {
        ip: count for ip, count in tcp_resolved_ips_counter.items()
        if stub_ips and ip in stub_ips
    }

    if tcp_confirmed_stubs or tcp_dns_fail_count > 0:
        console.print(f"\n[bold yellow]💡 ВОЗМОЖНО НЕ НАСТРОЕН DoH (TCP Тест):[/bold yellow]")
        if tcp_confirmed_stubs:
            ips_text = [f"[red]{ip}[/red] у {count} цел(ей)" for ip, count in tcp_confirmed_stubs.items()]
            console.print(f"DNS вернул IP заглушки: {', '.join(ips_text)}")
        if tcp_dns_fail_count > 0:
            console.print(f"У {tcp_dns_fail_count} TCP целей обнаружен DNS FAIL")
        console.print("[yellow]Рекомендация: Настройте DoH/DoT на вашем устройстве, роутере или VPN[/yellow]\n")

    if mixed > 0:
        console.print(
            "[dim]Смешанные результаты указывают на балансировку DPI у провайдера[/dim]"
        )

    return {
        "total": len(TCP_16_20_ITEMS),
        "ok": passed,
        "blocked": blocked,
        "mixed": mixed,
    }


async def main():
    console.clear()

    # Показываем информацию о DEBUG режиме
    if DEBUG_MODE:
        debug_panel = Panel(
            f"[bold yellow]DEBUG MODE ENABLED[/bold yellow]\n"
            f"OpenSSL: {ssl.OPENSSL_VERSION}\n"
            f"Python: {sys.version.split()[0]}\n"
            f"Platform: {sys.platform}\n"
            f"Debug domains: {DEBUG_DOMAINS if DEBUG_DOMAINS else 'ALL'}",
            title="[bold red]DEBUG INFO[/bold red]",
            border_style="red"
        )
        console.print(debug_panel)
        console.print()

    console.print(
        "[bold cyan]DPI Detector v1.2[/bold cyan] | "
        "[yellow]DNS + TCP/TLS + HTTP + TCP 16-20KB Test[/yellow]"
    )
    console.print(
        f"Тестирование {len(DOMAINS)} доменов + {len(TCP_16_20_ITEMS)} TCP 16-20KB целей."
    )
    console.print(
        f"[dim]Таймаут: {TIMEOUT}s (домены), {TIMEOUT_TCP_16_20}s (TCP 16-20KB) | "
        f"Потоков: {MAX_CONCURRENT}[/dim]"
    )
    console.print(
        f"[dim]Попыток: {DOMAIN_CHECK_RETRIES}x (домены), "
        f"{TCP_16_20_CHECK_RETRIES}x (TCP 16-20KB)[/dim]"
    )
    console.print(
        f"[dim]Порог вариативности DPI: {DPI_VARIANCE_THRESHOLD}% | "
        f"Диапазон TCP блока: {TCP_BLOCK_MIN_KB}-{TCP_BLOCK_MAX_KB}KB[/dim]\n"
        f"[dim]Только IPv4: {USE_IPV4_ONLY}[/dim]\n"
    )

    # Выбор тестов — спрашиваем один раз, запоминаем для повтора
    selection = await ask_test_selection()
    run_dns     = "1" in selection
    run_domains = "2" in selection
    run_tcp     = "3" in selection

    # Вопрос о сохранении в файл
    save_to_file = False
    result_path = None
    loop = asyncio.get_running_loop()
    try:
        save_raw = (await loop.run_in_executor(
            None, lambda: input("\nСохранять результаты в файл? [y/N]: ")
        )).strip().lower()
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt
    if save_raw in ("y", "yes", "д", "да"):
        save_to_file = True
        result_path = os.path.join(get_exe_dir(), "dpi_detector_results.txt")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    first_run = True

    # Основной цикл: тест → предложение повторить
    while True:
        stub_ips: set = set()
        dns_intercept_count = 0
        if run_dns and DNS_CHECK_ENABLED:
            stub_ips, dns_intercept_count = await check_dns_integrity()
        elif DNS_CHECK_ENABLED and (run_domains or run_tcp):
            stub_ips = await _collect_stub_ips_silently()

        domain_stats = None
        tcp_stats = None

        if run_domains:
            domain_stats = await run_domains_test(semaphore, stub_ips)

        if run_tcp:
            tcp_stats = await run_tcp_test(semaphore, stub_ips)

        # Итоговая сводка — показываем если хотя бы 2 теста запущено
        dns_stats = None
        if run_dns:
            dns_stats = {
                "intercept": dns_intercept_count,
                "total": len(DNS_CHECK_DOMAINS),
            }

        active_tests = sum([run_dns, run_domains, run_tcp])
        if active_tests >= 2:
            console.print()
            summary_lines = []

            if run_dns and dns_stats:
                dns_ok = dns_stats["total"] - dns_stats["intercept"]
                if dns_stats["intercept"] > 0:
                    summary_lines.append(
                        f"[bold]DNS[/bold]         "
                        f"[green]√ {dns_ok}/{dns_stats['total']} не подменяются[/green]"
                        f"  [red]× {dns_stats['intercept']} подмена[/red]"
                    )
                else:
                    summary_lines.append(
                        f"[bold]DNS[/bold]         "
                        f"[green]√ {dns_ok}/{dns_stats['total']} не подменяются[/green]"
                    )

            if domain_stats:
                d = domain_stats
                d_ok_pct = int(d["ok"] / d["total"] * 100) if d["total"] else 0
                summary_lines.append(
                    f"[bold]Домены[/bold]      "
                    f"[green]√ {d['ok']}/{d['total']} OK[/green]"
                    + (f"  [red]× {d['blocked']} заблок.[/red]" if d['blocked'] else "")
                    + (f"  [yellow]⏱ {d['timeout']} таймаут[/yellow]" if d['timeout'] else "")
                    + f"  [dim]({d_ok_pct}%)[/dim]"
                )

            if tcp_stats:
                t = tcp_stats
                t_ok_pct = int(t["ok"] / t["total"] * 100) if t["total"] else 0
                summary_lines.append(
                    f"[bold]TCP 16-20KB[/bold]  "
                    f"[green]√ {t['ok']}/{t['total']} OK[/green]"
                    + (f"  [red]× {t['blocked']} блок.[/red]" if t['blocked'] else "")
                    + (f"  [yellow]≈ {t['mixed']} смеш.[/yellow]" if t['mixed'] else "")
                    + f"  [dim]({t_ok_pct}%)[/dim]"
                )

            panel = Panel(
                "\n".join(summary_lines),
                title="[bold]Итог[/bold]",
                border_style="cyan",
                padding=(0, 1),
                expand=False,
            )
            console.print(panel)

        # Легенда — только при первом запуске
        if first_run:
            console.print("\n[bold]Легенда статусов:[/bold]")
            legend = [
                ("TLS DPI",   "DPI манипулирует или обрывает TLS соединение"),
                ("UNSUPP",    "Сервер не поддерживает TLS 1.3 (не блокировка)"),
                ("TLS MITM",  "Man-in-the-Middle: подмена/проблемы с сертификатом"),
                ("TLS BLOCK", "Блокировка версии TLS или протокола"),
                ("SSL ERR",   "SSL/TLS ошибка (часто проблемы совместимости CDN/сервера)"),
                ("ISP PAGE",  "Редирект на страницу провайдера или блок-страница"),
                ("BLOCKED",   "HTTP 451 (Недоступно по юридическим причинам)"),
                ("TIMEOUT",   "Таймаут соединения или чтения"),
                ("DNS FAIL",  "Не удалось разрешить доменное имя"),
                ("OK / REDIR","Сайт доступен (может быть редирект)"),
            ]
            for term, desc in legend:
                console.print(f"[dim]• [cyan]{term:<12}[/cyan] = {desc}[/dim]")
            first_run = False

        console.print("\n[bold green]Проверка завершена.[/bold green]")

        # Сохранение в файл (перезаписываем при каждом прогоне)
        if save_to_file and result_path:
            try:
                text = console.export_text()
                with open(result_path, "w", encoding="utf-8") as f:
                    f.write(text)
                console.print(f"[dim]Результаты сохранены: [cyan]{result_path}[/cyan][/dim]")
            except Exception as e:
                console.print(f"[yellow]Не удалось сохранить файл: {e}[/yellow]")

        # Предложение повторить — запускаем input в executor чтобы реально ждал
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: input("\nНажмите Enter чтобы запустить тест ещё раз, Ctrl+C для выхода... ")
            )
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt
        console.print()


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Прервано пользователем.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Критическая ошибка:[/bold red] {e}")
        traceback.print_exc()
        if sys.platform == 'win32':
            print("\nНажмите Enter для выхода...")
            input()