#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse


LOGGER = logging.getLogger("vpn_route_bypass")

# ---------------------------------------------------------------------------
# 常量：fake-ip 检测、DoH 解析、hosts 标记段
# ---------------------------------------------------------------------------
# 常见 fake-ip 代理（Clash / Mihomo / Surge / SakuraCat 等）使用的保留网段。
# 当系统解析到的 IP 落在此类网段时，认为 DNS 已被代理劫持，需要改用 DoH 取真实 IP。
DEFAULT_FAKE_IP_RANGES = ["198.18.0.0/15", "100.64.0.0/10"]

# 默认 DoH 端点：通过 HTTPS 获取权威 A 记录，绕过 UDP/TCP 53 劫持。
# {host} 占位符会被替换为待解析域名；返回 JSON 需包含 Answer 数组。
DEFAULT_DOH_URLS = [
    "https://223.5.5.5/resolve?name={host}&type=A",
    "https://dns.alidns.com/resolve?name={host}&type=A",
]

# hosts 文件路径（按平台）
HOSTS_PATHS = {
    "Darwin": "/etc/hosts",
    "Windows": r"C:\Windows\System32\drivers\etc\hosts",
    "Linux": "/etc/hosts",
}

# hosts 标记段：只增删两个标记之间的行，绝不触碰用户其他内容
HOSTS_MARK_BEGIN = "# === VPN-ROUTE-BYPASS-BEGIN ==="
HOSTS_MARK_END = "# === VPN-ROUTE-BYPASS-END ==="


def run_command(command: Sequence[str], check: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout: {result.stdout.strip()}\nstderr: {result.stderr.strip()}"
        )
    return result


def is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def looks_like_prefix(prefix: str) -> Optional[str]:
    """
    Extract hostname from strings like:
      - https://example.com/path
      - example.com/path
      - *.example.com
      - example.com
      - 203.0.113.10
    """
    value = prefix.strip()
    if not value:
        return None

    host = ""
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        value = re.sub(r"^\\*\\.", "", value)
        host = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()

    host = (host or "").strip().lower()
    return host or None


def resolve_ipv4_addresses(hosts: Iterable[str]) -> Set[str]:
    ips: Set[str] = set()
    for host in hosts:
        if not host:
            continue
        if is_ip(host):
            if ipaddress.ip_address(host).version == 4:
                ips.add(host)
            continue

        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        except socket.gaierror as exc:
            LOGGER.warning("Failed to resolve %s: %s", host, exc)
            continue

        for info in infos:
            address = info[4][0]
            try:
                if ipaddress.ip_address(address).version == 4:
                    ips.add(address)
            except ValueError:
                continue

    return ips


# ---------------------------------------------------------------------------
# fake-ip 检测与真实 IP 解析
# ---------------------------------------------------------------------------
def is_suspicious_ip(ip: str, fake_ranges: Sequence[str]) -> bool:
    """判断 IP 是否落在 fake-ip 等保留/可疑网段（说明 DNS 可能被代理劫持）。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    for rng in fake_ranges:
        try:
            if addr in ipaddress.ip_network(rng, strict=False):
                return True
        except ValueError:
            continue
    return False


def resolve_via_doh(host: str, urls: Sequence[str], timeout: int = 8) -> List[str]:
    """通过 DoH（HTTPS DNS）解析 A 记录，绕过 fake-ip DNS 劫持。

    支持的响应格式：JSON 中包含 ``Answer`` 数组（阿里 DoH、Cloudflare DoH 通用），
    每条 ``type == 1``（A 记录）的 ``data`` 即 IPv4 地址。
    """
    for url in urls:
        try:
            full_url = str(url).replace("{host}", host)
            req = urllib.request.Request(
                full_url, headers={"User-Agent": "vpn-route-bypass/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = resp.read().decode("utf-8", errors="replace")
            data = json.loads(payload)
        except Exception as exc:
            LOGGER.debug("DoH resolve failed via %s for %s: %s", url, host, exc)
            continue

        answers = data.get("Answer") if isinstance(data, dict) else None
        if not isinstance(answers, list):
            continue
        ips: List[str] = []
        for a in answers:
            if not isinstance(a, dict):
                continue
            if a.get("type") not in (1, "A"):
                continue
            value = str(a.get("data", ""))
            if is_ip(value) and ipaddress.ip_address(value).version == 4:
                ips.append(value)
        if ips:
            LOGGER.info("DoH resolved %s -> %s", host, ",".join(sorted(set(ips))))
            return ips
    return []


def resolve_real_addresses(host: str, cfg: Dict[str, object]) -> Set[str]:
    """智能解析一个主机的真实 IPv4 地址。

    策略：
    1. 先用系统 ``getaddrinfo`` 解析；
    2. 若结果为空、或全部落在 fake-ip/保留网段（DNS 被劫持），改用 DoH 取真实 IP；
    3. DoH 也失败时回退到系统结果（尽力而为）。
    """
    fake_ranges = cfg.get("fake_ip_ranges", DEFAULT_FAKE_IP_RANGES)
    if not isinstance(fake_ranges, list):
        fake_ranges = DEFAULT_FAKE_IP_RANGES
    fake_ranges = [str(r) for r in fake_ranges]

    system_ips = resolve_ipv4_addresses([host])
    real_ips = {ip for ip in system_ips if not is_suspicious_ip(ip, fake_ranges)}
    if real_ips:
        return real_ips

    if system_ips:
        LOGGER.warning(
            "System DNS returned suspicious IPs for %s: %s (probably fake-ip hijack), "
            "trying DoH instead",
            host,
            ",".join(sorted(system_ips)),
        )

    doh_enabled = bool(cfg.get("doh_enabled", True))
    if doh_enabled:
        doh_urls = cfg.get("doh_urls", DEFAULT_DOH_URLS)
        if not isinstance(doh_urls, list):
            doh_urls = DEFAULT_DOH_URLS
        doh_ips = resolve_via_doh(host, [str(u) for u in doh_urls])
        if doh_ips:
            return set(doh_ips)

    return system_ips


# ---------------------------------------------------------------------------
# hosts 文件标记段管理
# ---------------------------------------------------------------------------
def hosts_path() -> str:
    return HOSTS_PATHS.get(platform.system(), "/etc/hosts")


def read_hosts_text() -> str:
    path = hosts_path()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as exc:
        LOGGER.error("Failed to read hosts file %s: %s", path, exc)
        return ""


def _strip_marked_block(text: str) -> str:
    """去掉两个标记之间的内容，保留其余部分（含系统原始行）。"""
    lines = text.splitlines()
    kept: List[str] = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if stripped == HOSTS_MARK_BEGIN:
            in_block = True
            continue
        if stripped == HOSTS_MARK_END:
            in_block = False
            continue
        if not in_block:
            kept.append(line)
    body = "\n".join(kept).rstrip("\n")
    if body:
        body += "\n"
    return body


def _write_hosts_text(text: str) -> bool:
    path = hosts_path()
    tmp = path + ".vpnbypass.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
        return True
    except OSError as exc:
        LOGGER.error("Failed to write hosts file %s (need admin?): %s", path, exc)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def update_hosts_marked(host_ip_map: Dict[str, str]) -> bool:
    """把「域名 -> 真实IP」写入 hosts 的托管标记段（幂等，可重复调用）。

    host_ip_map: {hostname: ip}，每个域名一个首选 IP。
    """
    body = _strip_marked_block(read_hosts_text())
    block_lines = [HOSTS_MARK_BEGIN]
    for host in sorted(host_ip_map):
        block_lines.append(f"{host_ip_map[host]}\t{host}")
    block_lines.append(HOSTS_MARK_END)
    return _write_hosts_text(body + "\n".join(block_lines) + "\n")


def clear_hosts_marked() -> bool:
    """移除 hosts 中由本工具管理的标记段。"""
    body = _strip_marked_block(read_hosts_text())
    if not body:
        return True
    return _write_hosts_text(body)


def parse_ip_overrides(raw: object) -> Dict[str, str]:
    """把 ``host_ip_overrides`` 配置规范化为 {hostname: ip}。

    key 支持带协议前缀（如 ``https://intra.school.example``）或纯域名（``intra.school.example``）；
    忽略非法 IP、IPv6 或无法解析成域名的 key。
    """
    overrides: Dict[str, str] = {}
    if not isinstance(raw, dict):
        return overrides
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        host = looks_like_prefix(key)
        ip = value.strip()
        if host and is_ip(ip) and ipaddress.ip_address(ip).version == 4:
            overrides[host] = ip
    return overrides


def build_target_host_map(cfg: Dict[str, object]) -> Dict[str, Set[str]]:
    """解析配置中所有白名单前缀，得到 {hostname: set(ip)}（真实 IP）。

    优先级：
    1. ``host_ip_overrides`` 中为域名手动指定的直连 IP（如校内站的内网地址，
       公共 DNS 中不存在、无法自动解析，必须手动指定）；
    2. 否则走自动解析：系统解析 -> fake-ip 检测 -> DoH 兜底。
    """
    raw_prefixes = cfg.get("prefixes", [])
    if not isinstance(raw_prefixes, list):
        raise ValueError("`prefixes` in config must be a list")

    hosts = collect_target_prefixes(raw_prefixes)
    if not hosts:
        LOGGER.warning("No valid prefixes in config")
        return {}

    overrides = parse_ip_overrides(cfg.get("host_ip_overrides"))

    host_map: Dict[str, Set[str]] = {}
    for host in sorted(hosts):
        if host in overrides:
            LOGGER.info("Using configured IP override for %s -> %s", host, overrides[host])
            host_map[host] = {overrides[host]}
            continue
        ips = resolve_real_addresses(host, cfg)
        if ips:
            host_map[host] = ips
        else:
            LOGGER.warning("No resolvable IP for host %s", host)
    return host_map


class RouteManager:
    def __init__(self, local_gateway: Optional[str] = None, dry_run: bool = False):
        self.local_gateway = local_gateway
        self.dry_run = dry_run
        self.gateway = self.find_local_gateway()

    def find_local_gateway(self) -> str:
        raise NotImplementedError

    def add_route(self, ip: str) -> bool:
        raise NotImplementedError

    def remove_route(self, ip: str) -> bool:
        raise NotImplementedError


class MacRouteManager(RouteManager):
    vpn_interface_keywords = (
        "utun",
        "ppp",
        "ipsec",
        "tap",
        "tun",
        "vpn",
        "wgvpn",
        "wg",
    )

    def _is_vpn_interface(self, interface: str) -> bool:
        if not interface:
            return False
        name = interface.lower()
        return name.startswith(self.vpn_interface_keywords) or any(k in name for k in self.vpn_interface_keywords)

    def find_local_gateway(self) -> str:
        if self.local_gateway:
            return self.local_gateway

        # Try parsing all default routes and pick one that is not obviously a VPN interface.
        output = run_command(["netstat", "-rn", "-f", "inet"]).stdout
        defaults = []
        header = None
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if parts[0] == "Destination" and "Gateway" in parts and "Netif" in parts:
                header = {name: idx for idx, name in enumerate(parts)}
                continue
            if parts[0] == "Internet:" or parts[0] == "Routing":
                header = None
                continue
            if header and parts[0] == "default":
                gw_idx = header.get("Gateway")
                if_idx = header.get("Netif")
                if gw_idx is None or if_idx is None:
                    continue
                if gw_idx < len(parts) and if_idx < len(parts):
                    gw = parts[gw_idx]
                    iface = parts[if_idx]
                    if is_ip(gw):
                        defaults.append((iface, gw))

        for iface, gw in defaults:
            if not self._is_vpn_interface(iface):
                LOGGER.info("Mac: selected gateway %s on interface %s", gw, iface)
                return gw

        if defaults:
            gw = defaults[0][1]
            LOGGER.warning("Mac: no non-VPN default route found, fallback to %s", gw)
            return gw

        fallback = run_command(["route", "-n", "get", "default"]).stdout
        m_gw = re.search(r"^\s*gateway:\s+([^\n]+)$", fallback, re.M)
        m_iface = re.search(r"^\s*interface:\s+([^\n]+)$", fallback, re.M)
        if m_gw:
            gw = m_gw.group(1).strip()
            iface = m_iface.group(1).strip() if m_iface else ""
            if is_ip(gw):
                if not self._is_vpn_interface(iface):
                    LOGGER.info("Mac: selected fallback gateway %s on interface %s", gw, iface)
                else:
                    LOGGER.warning("Mac: fallback route may still point to VPN interface (%s)", iface)
                return gw

        raise RuntimeError("Could not detect local gateway on macOS.")

    def add_route(self, ip: str) -> bool:
        if self.dry_run:
            LOGGER.info("[dry-run] mac route add -host %s via %s", ip, self.gateway)
            return True

        cmd = ["route", "-n", "add", "-host", ip, self.gateway]
        result = run_command(cmd)
        if result.returncode == 0:
            LOGGER.info("Added mac route: %s -> %s", ip, self.gateway)
            return True

        if "file exists" in result.stderr.lower() or "File exists" in result.stderr:
            LOGGER.debug("Route for %s already exists", ip)
            return True

        LOGGER.error("Failed to add route for %s: %s", ip, result.stderr.strip())
        return False

    def remove_route(self, ip: str) -> bool:
        if self.dry_run:
            LOGGER.info("[dry-run] mac route delete -host %s", ip)
            return True

        result = run_command(["route", "-n", "delete", "-host", ip])
        if result.returncode == 0:
            LOGGER.info("Removed mac route: %s", ip)
            return True

        if "not in table" in result.stderr.lower() or "not found" in result.stderr.lower():
            LOGGER.debug("Route for %s already absent", ip)
            return True

        LOGGER.error("Failed to remove route for %s: %s", ip, result.stderr.strip())
        return False


class WindowsRouteManager(RouteManager):
    def find_local_gateway(self) -> str:
        if self.local_gateway:
            return self.local_gateway

        output = run_command(["route", "print", "-4"]).stdout
        in_active_routes = False
        rows: List[tuple[int, str]] = []

        for line in output.splitlines():
            if "Active Routes:" in line:
                in_active_routes = True
                continue
            if "Persistent Routes:" in line:
                in_active_routes = False
                continue
            if not in_active_routes:
                continue
            if not line.strip() or line.lstrip().startswith("===="):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            # Typical line: 0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.100  25
            dest, mask, gateway = parts[0], parts[1], parts[2]
            metric_str = parts[-1]
            if dest != "0.0.0.0" or mask != "0.0.0.0":
                continue
            if not is_ip(gateway) or gateway in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}:
                continue
            try:
                metric = int(metric_str)
            except ValueError:
                metric = 10_000
            rows.append((metric, gateway))

        if rows:
            rows.sort(key=lambda item: item[0])
            gw = rows[0][1]
            LOGGER.info("Windows: selected gateway %s", gw)
            return gw

        raise RuntimeError("Could not detect local gateway on Windows.")

    def add_route(self, ip: str) -> bool:
        if self.dry_run:
            LOGGER.info("[dry-run] route add %s mask 255.255.255.255 %s", ip, self.gateway)
            return True

        result = run_command(["route", "add", ip, "MASK", "255.255.255.255", self.gateway])
        if result.returncode == 0:
            LOGGER.info("Added Windows route: %s -> %s", ip, self.gateway)
            return True

        if "存在" in result.stderr or "exists" in result.stderr.lower():
            LOGGER.debug("Route for %s already exists", ip)
            return True

        LOGGER.error("Failed to add route for %s: %s", ip, result.stderr.strip())
        return False

    def remove_route(self, ip: str) -> bool:
        if self.dry_run:
            LOGGER.info("[dry-run] route delete %s", ip)
            return True

        result = run_command(["route", "delete", ip])
        if result.returncode == 0:
            LOGGER.info("Removed Windows route: %s", ip)
            return True

        if "not found" in result.stderr.lower() or "找不到" in result.stderr:
            LOGGER.debug("Route for %s already absent", ip)
            return True

        LOGGER.error("Failed to remove route for %s: %s", ip, result.stderr.strip())
        return False


def _state_file_from_config(config_path: Path, explicit: Optional[str]) -> Path:
    return (config_path.parent / (explicit or ".vpn_route_bypass_state.json")).resolve()


def load_state(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError:
            return set()
    values = raw.get("ips") if isinstance(raw, dict) else None
    if not isinstance(values, list):
        return set()
    return {item for item in values if isinstance(item, str)}


def save_state(path: Path, ips: Set[str]) -> None:
    data = {"ips": sorted(ips)}
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_config(path: Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def collect_target_prefixes(values: Iterable[object]) -> Set[str]:
    hosts: Set[str] = set()
    for item in values:
        if not isinstance(item, str):
            continue
        host = looks_like_prefix(item)
        if host:
            hosts.add(host)
    return hosts


def build_targets(config_path: Path, cfg: Dict[str, object]) -> Set[str]:
    """返回所有白名单域名解析出的真实 IPv4 集合（兼容旧调用）。"""
    host_map = build_target_host_map(cfg)
    all_ips: Set[str] = set()
    for ips in host_map.values():
        all_ips.update(ips)
    return all_ips


def make_manager(platform_name: str, local_gateway: Optional[str], dry_run: bool) -> RouteManager:
    if platform_name == "Darwin":
        return MacRouteManager(local_gateway=local_gateway, dry_run=dry_run)
    if platform_name == "Windows":
        return WindowsRouteManager(local_gateway=local_gateway, dry_run=dry_run)
    raise RuntimeError(f"Unsupported platform: {platform_name}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Add host routes for selected domains to bypass VPN tunnel traffic.",
    )
    parser.add_argument("--config", default="config.json", help="Path to JSON config file")
    parser.add_argument("--once", action="store_true", help="Sync once and exit")
    parser.add_argument("--cleanup", action="store_true", help="Delete all managed routes and exit")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level",
    )
    return parser.parse_args()


def sync_once(manager: RouteManager, config_path: Path, cfg: Dict[str, object], state_path: Path) -> None:
    state = load_state(state_path)

    # 1) 解析白名单域名 -> 真实 IP（自动识别并绕过 fake-ip DNS 劫持）
    host_map = build_target_host_map(cfg)
    current: Set[str] = set()
    for ips in host_map.values():
        current.update(ips)

    # 2) 同步 /etc/hosts 托管标记段：让应用层解析直接拿到真实 IP
    manage_hosts = bool(cfg.get("manage_hosts", True))
    if manager.dry_run:
        if manage_hosts and host_map:
            preview = {h: sorted(ips)[0] for h, ips in host_map.items() if ips}
            LOGGER.info("[dry-run] would update hosts entries: %s", preview)
    elif manage_hosts and host_map:
        host_ip_map = {h: sorted(ips)[0] for h, ips in host_map.items() if ips}
        if update_hosts_marked(host_ip_map):
            LOGGER.info("Updated hosts file with %d entry(ies)", len(host_ip_map))
        else:
            LOGGER.error("Failed to update hosts file (need admin privileges?)")
    elif not manage_hosts:
        clear_hosts_marked()

    # 3) 路由同步：为真实 IP 添加 host 路由（绕过代理 TUN），并清理不再需要的路由
    #    每次对全部目标 IP 幂等重加（route add 对已存在的路由会安全跳过），
    #    避免「路由被代理清掉 / dry-run 污染状态文件」后永远不再补加。
    added_count = 0
    for ip in sorted(current):
        if manager.add_route(ip):
            state.add(ip)
            added_count += 1

    removed_count = 0
    stale = state - current
    for ip in sorted(stale):
        if manager.remove_route(ip):
            state.discard(ip)
            removed_count += 1

    if manager.dry_run:
        # dry-run 只是演练：不落盘状态，避免污染下次真实运行
        LOGGER.info(
            "[dry-run] route add/ensure: %d, remove: %d, state would be: %s",
            added_count,
            removed_count,
            sorted(state),
        )
        return

    save_state(state_path, state)
    LOGGER.info(
        "Route sync complete. hosts=%d, managed=%d, ensured=%d, removed=%d, total=%d",
        len(host_map),
        len(state),
        added_count,
        removed_count,
        len(state),
    )


def cleanup(manager: RouteManager, state_path: Path) -> None:
    state = load_state(state_path)
    if state:
        for ip in sorted(state):
            manager.remove_route(ip)
        save_state(state_path, set())
    else:
        LOGGER.info("No managed routes to clean up.")

    if clear_hosts_marked():
        LOGGER.info("Removed VPN-ROUTE-BYPASS section from hosts file.")
    else:
        LOGGER.error("Failed to remove hosts managed section (need admin privileges?).")


def main() -> None:
    global args
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")

    config_path = Path(args.config).resolve()
    cfg = load_config(config_path)

    interval = int(cfg.get("interval_seconds", 120))
    local_gateway = cfg.get("local_gateway")
    local_gateway = local_gateway if isinstance(local_gateway, str) and local_gateway else None
    state_path = _state_file_from_config(config_path, cfg.get("state_file") if isinstance(cfg.get("state_file"), str) else None)
    dry_run = bool(cfg.get("dry_run", False))

    manager = make_manager(platform.system(), local_gateway=local_gateway, dry_run=dry_run)

    if args.cleanup:
        cleanup(manager, state_path)
        return

    if args.once:
        sync_once(manager, config_path, cfg, state_path)
        return

    LOGGER.info("Running as daemon. Interval: %d seconds", interval)
    while True:
        sync_once(manager, config_path, cfg, state_path)
        time.sleep(max(15, interval))


if __name__ == "__main__":
    main()
