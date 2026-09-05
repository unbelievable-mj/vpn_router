#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = BASE_DIR / "config.json"
EXAMPLE_CONFIG = BASE_DIR / "config.example.json"
APP_NAME = "VPN Route Bypass"


class BypassTrayApp:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.engine_script = BASE_DIR / "vpn_route_bypass.py"
        self.process: Optional[subprocess.Popen[str]] = None
        self.icon: Optional[pystray.Icon] = None
        self._status_lines: List[str] = []
        self._stop_monitor = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None

    def _log_to_status(self, message: str) -> None:
        self._status_lines.append(message)
        self._status_lines = self._status_lines[-6:]

    def _notify(self, title: str, message: str = "") -> None:
        if self.icon is None:
            return
        try:
            self.icon.notify(message, title)
        except Exception:
            pass

    def _ensure_config(self) -> None:
        if self.config_path.exists():
            return

        if EXAMPLE_CONFIG.exists():
            self.config_path.write_text(
                EXAMPLE_CONFIG.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            return

        default_cfg = {
            "prefixes": ["https://vpn.school.example", "https://intra.company.example"],
            "interval_seconds": 120,
            "local_gateway": None,
            "state_file": ".vpn_route_bypass_state.json",
            "dry_run": False,
            "manage_hosts": True,
            "doh_enabled": True,
            "doh_urls": [
                "https://223.5.5.5/resolve?name={host}&type=A",
                "https://dns.alidns.com/resolve?name={host}&type=A",
            ],
            "fake_ip_ranges": ["198.18.0.0/15", "100.64.0.0/10"],
            "host_ip_overrides": {},
        }
        self.config_path.write_text(
            json.dumps(default_cfg, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _read_config(self) -> Dict[str, Any]:
        self._ensure_config()
        with self.config_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _write_config(self, cfg: Dict[str, Any]) -> None:
        self.config_path.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _state_path(self, cfg: Dict[str, Any]) -> Path:
        state_file = cfg.get("state_file", ".vpn_route_bypass_state.json")
        if not isinstance(state_file, str) or not state_file.strip():
            state_file = ".vpn_route_bypass_state.json"
        return (self.config_path.parent / state_file).resolve()

    def _read_state(self) -> Tuple[int, List[str]]:
        try:
            cfg = self._read_config()
            path = self._state_path(cfg)
            if not path.exists():
                return 0, []
            raw = json.loads(path.read_text(encoding="utf-8"))
            ips = raw.get("ips", []) if isinstance(raw, dict) else []
            if not isinstance(ips, list):
                ips = []
            values = [ip for ip in ips if isinstance(ip, str)]
            return len(values), values
        except Exception:
            return 0, []

    def _build_icon(self, running: bool) -> Image.Image:
        color = (0, 150, 0) if running else (130, 130, 130)
        bg = (0, 0, 0, 0)
        img = Image.new("RGBA", (64, 64), bg)
        draw = ImageDraw.Draw(img)
        draw.rounded_rectangle((6, 6, 58, 58), radius=14, fill=color)
        draw.rounded_rectangle((12, 12, 52, 52), radius=10, fill=(255, 255, 255, 220))
        draw.text((22, 18), "VPN", fill=color)
        if running:
            draw.text((18, 36), "ON", fill=color)
        else:
            draw.text((16, 36), "OFF", fill=color)
        return img

    def _engine_cmd(self, *extra: str) -> List[str]:
        return [sys.executable, str(self.engine_script), "--config", str(self.config_path), *extra]

    def _run_engine_once(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._engine_cmd(*extra),
            text=True,
            capture_output=True,
        )

    def _is_process_alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _start_service(self) -> bool:
        if self._is_process_alive():
            self._log_to_status("服务已经在运行")
            return False
        cmd = self._engine_cmd()
        kwargs: Dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if platform.system() == "Windows":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        try:
            self.process = subprocess.Popen(cmd, **kwargs)
        except Exception as exc:
            self._log_to_status(f"启动失败: {exc}")
            self._notify("启动失败", str(exc))
            self._refresh_menu()
            return False

        # quick stale-process check
        time.sleep(0.2)
        if self.process.poll() is not None:
            self._log_to_status("启动失败：请检查 Python 权限是否是管理员/管理员终端")
            self._notify("启动失败", "服务进程立即退出，请使用管理员权限运行")
            self.process = None
            self._refresh_menu()
            return False

        self._log_to_status("服务已启动")
        self._notify("VPN 绕过", "服务已启动")
        self._refresh_menu()
        return True

    def _stop_service(self) -> bool:
        if not self._is_process_alive():
            self._log_to_status("服务未运行")
            return False

        p = self.process
        if p is None:
            return False

        if platform.system() == "Windows":
            p.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                p.wait(timeout=2)
            except Exception:
                p.terminate()
                p.wait(timeout=2)
        else:
            p.terminate()
            try:
                p.wait(timeout=2)
            except Exception:
                p.kill()
                p.wait(timeout=2)

        self.process = None
        self._log_to_status("服务已停止")
        self._notify("VPN 绕过", "服务已停止")
        self._refresh_menu()
        return True

    def _cleanup_routes(self) -> None:
        result = self._run_engine_once("--cleanup")
        if result.returncode == 0:
            self._log_to_status("已清理全部托管路由")
            self._notify("VPN 绕过", "已清理全部托管路由")
        else:
            self._log_to_status("清理失败" + (": " + result.stderr.strip() if result.stderr else ""))
            self._notify("清理失败", result.stderr.strip() or "请查看日志")
        self._refresh_menu()

    def _sync_once(self) -> None:
        result = self._run_engine_once("--once")
        if result.returncode == 0:
            self._log_to_status("已执行一次同步")
        else:
            self._log_to_status("同步失败: " + result.stderr.strip())
        self._refresh_menu()

    def _restart_service(self) -> None:
        if self._is_process_alive():
            self._stop_service()
        self._start_service()

    def _refresh_menu(self) -> None:
        if self.icon is None:
            return
        self.icon.icon = self._build_icon(self._is_process_alive())
        total, _ = self._read_state()
        cfg = self._read_config()
        prefix_count = len(cfg.get("prefixes", []) if isinstance(cfg.get("prefixes", []), list) else [])
        self.icon.title = f"{APP_NAME} | {self._status_text(prefix_count, total)}"

        running = self._is_process_alive()

        def on_toggle_service(icon, _item=None):
            if running:
                threading.Thread(target=self._stop_service, daemon=True).start()
            else:
                threading.Thread(target=self._start_service, daemon=True).start()

        def on_sync(icon, _item=None):
            threading.Thread(target=self._sync_once, daemon=True).start()

        def on_cleanup(icon, _item=None):
            threading.Thread(target=self._cleanup_routes, daemon=True).start()

        def on_add_site(icon, _item=None):
            threading.Thread(target=self._add_site, daemon=True).start()

        def on_reset(icon, _item=None):
            threading.Thread(target=self._reset_config, daemon=True).start()

        def on_remove_site(value: str):
            def _inner(_icon, _item=None):
                threading.Thread(target=self._remove_site, args=(value,), daemon=True).start()

            return _inner

        def on_quit(icon, _item=None):
            threading.Thread(target=self._quit, args=(icon,), daemon=True).start()

        def on_clear_sites(_icon, _item=None):
            threading.Thread(target=self._clear_sites, daemon=True).start()

        def build_manage_menu() -> pystray.Menu:
            items: List[item] = []
            if not isinstance(cfg.get("prefixes", []), list) or not cfg["prefixes"]:
                return pystray.Menu(
                    item("（空）", lambda _i, _m=None: None, enabled=False),
                )

            for p in cfg["prefixes"]:
                items.append(item(p, on_remove_site(p)))
            items.append(item("清空全部", on_clear_sites))
            return pystray.Menu(*items)

        menu = pystray.Menu(
            item("▶ 启动服务" if not running else "■ 停止服务", on_toggle_service),
            item("添加白名单", on_add_site),
            item("管理站点", build_manage_menu()),
            item("重置配置", on_reset),
            item("退出", on_quit),
        )

        self.icon.menu = menu
        try:
            self.icon.update_menu()
        except Exception:
            pass

    def _status_text(self, prefix_count: int, route_count: int) -> str:
        return (
            f"[{ 'ON' if self._is_process_alive() else 'OFF' }] "
            f"{prefix_count}站点 {route_count}路由"
        )

    def _monitor(self) -> None:
        while not self._stop_monitor.is_set():
            self._refresh_menu()
            time.sleep(2)

    def _normalize_prefix(self, value: str) -> Optional[str]:
        raw = value.strip()
        if not raw:
            return None
        if "://" in raw:
            raw_host = urlparse(raw).hostname or ""
        else:
            raw_host = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            if raw_host.startswith("*."):
                raw_host = raw_host[2:]
        host = raw_host.strip().lower()
        return host or None

    def _prompt_text(self, title: str, message: str, default: str = "") -> Optional[str]:
        escaped_title = title.replace("\\", "\\\\").replace("\"", "\\\"")
        escaped_message = message.replace("\\", "\\\\").replace("\"", "\\\"")
        if platform.system() == "Darwin":
            default_value = default.replace("\\", "\\\\").replace("\"", "\\\"")
            script = (
                f'display dialog "{escaped_message}" '
                f'with title "{escaped_title}" '
                f'default answer "{default_value}" buttons {{"确定", "取消"}} default button "确定"'
            )
            result = subprocess.run(
                ["osascript", "-e", f'text returned of ({script})'],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            return result.stdout.strip()

        if platform.system() == "Windows":
            default_value = default.replace("'", "''")
            message_value = escaped_message.replace("'", "''")
            title_value = escaped_title.replace("'", "''")
            script = (
                "[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic');"
                f"$result = [Microsoft.VisualBasic.Interaction]::InputBox('{message_value}','{title_value}','{default_value}');"
                "if ($null -ne $result -and $result -ne '') { $result }"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            value = result.stdout.strip()
            return value if value else None

        return None

    def _prompt_confirm(self, title: str, message: str) -> bool:
        if platform.system() == "Darwin":
            script = (
                f'display dialog "{title}: {message}" '
                'buttons {"取消", "确定"} default button "取消" with icon stop'
            )
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0

        if platform.system() == "Windows":
            message_value = message.replace("'", "''")
            title_value = title.replace("'", "''")
            script = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                f"$r = [System.Windows.Forms.MessageBox]::Show('{message_value}','{title_value}', "
                "[System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning); "
                "if ($r -eq [System.Windows.Forms.DialogResult]::Yes) { Write-Output 'yes' }"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0 and result.stdout.strip() == "yes"

        return False

    def _add_site(self) -> None:
        raw = self._prompt_text(
            "添加白名单",
            "请输入要走本机网络的网站前缀，支持多个，每行一个。",
        )
        if raw is None or not raw.strip():
            return

        new_prefixes: List[str] = []
        for line in raw.splitlines():
            prefix = self._normalize_prefix(line)
            if prefix and prefix not in new_prefixes:
                new_prefixes.append(prefix)

        if not new_prefixes:
            self._notify("添加失败", "未解析到有效站点前缀")
            return

        cfg = self._read_config()
        prefixes = cfg.get("prefixes", [])
        if not isinstance(prefixes, list):
            prefixes = []

        for p in new_prefixes:
            if p not in prefixes:
                prefixes.append(p)

        cfg["prefixes"] = prefixes
        self._write_config(cfg)
        self._sync_once()
        self._refresh_menu()
        self._notify("添加成功", f"已添加 {len(new_prefixes)} 个白名单站点")

    def _remove_site(self, site: str) -> None:
        cfg = self._read_config()
        prefixes = cfg.get("prefixes", [])
        if not isinstance(prefixes, list):
            return
        cfg["prefixes"] = [p for p in prefixes if p != site]
        self._write_config(cfg)
        self._sync_once()
        self._refresh_menu()
        self._notify("站点已移除", site)

    def _clear_sites(self) -> None:
        cfg = self._read_config()
        cfg["prefixes"] = []
        self._write_config(cfg)
        self._sync_once()
        self._refresh_menu()
        self._notify("站点已清空", "白名单列表已清空")

    def _reset_config(self) -> None:
        if not self._prompt_confirm("重置配置", "确定要恢复为示例配置吗？"):
            return

        if EXAMPLE_CONFIG.exists():
            target = EXAMPLE_CONFIG.read_text(encoding="utf-8")
        else:
            target = json.dumps(
                {
                    "prefixes": [
                        "https://vpn.school.example",
                        "https://intra.company.example",
                    ],
                    "interval_seconds": 120,
                    "local_gateway": None,
                    "state_file": ".vpn_route_bypass_state.json",
                    "dry_run": False,
                    "manage_hosts": True,
                    "doh_enabled": True,
                    "doh_urls": [
                        "https://223.5.5.5/resolve?name={host}&type=A",
                        "https://dns.alidns.com/resolve?name={host}&type=A",
                    ],
                    "fake_ip_ranges": ["198.18.0.0/15", "100.64.0.0/10"],
                    "host_ip_overrides": {},
                },
                ensure_ascii=False,
                indent=2,
            ) + "\\n"

        self.config_path.write_text(target, encoding="utf-8")
        was_running = self._is_process_alive()
        if was_running:
            self._stop_service()
        self._run_engine_once("--cleanup")
        if was_running:
            self._start_service()
        self._refresh_menu()
        self._notify("配置已重置", "已恢复为示例配置")

    def _quit(self, icon: Optional[pystray.Icon] = None) -> None:
        self._stop_monitor.set()
        try:
            self._stop_service()
        except Exception:
            pass
        if icon is not None:
            icon.stop()

    def run(self) -> None:
        self._ensure_config()

        icon_image = self._build_icon(self._is_process_alive())
        self.icon = pystray.Icon("vpn-route-bypass", icon_image, APP_NAME, menu=pystray.Menu())
        self._refresh_menu()

        self._monitor_thread = threading.Thread(target=self._monitor, daemon=True)
        self._monitor_thread.start()

        try:
            self.icon.run()
        finally:
            self._quit(self.icon)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VPN route bypass tray app")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="Path to route-bypass config file",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    app = BypassTrayApp(Path(args.config).resolve())
    app.run()
